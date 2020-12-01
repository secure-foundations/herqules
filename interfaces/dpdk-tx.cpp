#include "dpdk-tx.h"
#include "syscalls.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_lcore.h>

// std::mutex::lock() can throw system_error
void std::__throw_system_error(int err) { abort(); }

namespace HQ::DPDK {

#ifndef HQ_INTERFACE_DPDK_SAME_PROCESS
static FILE *get_logfile() {
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s.%ld.tx.log", DPDK_LOG_PATH,
             RAW_SYSCALL(0, SYS_getpid));
    return fdopen(RAW_SYSCALL(3, SYS_open, reinterpret_cast<uintptr_t>(path),
                              O_CREAT | O_CLOEXEC | O_SYNC | O_WRONLY,
                              S_IRUSR | S_IRGRP | S_IWUSR),
                  "w");
}
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */

unsigned TX::init_port(uint16_t port) {
    struct rte_eth_dev_info device_info;
    struct rte_eth_conf port_conf = {
        // Autonegotiate link speed
        .link_speeds = ETH_LINK_SPEED_AUTONEG,
        // Disable multiple queues
        .rxmode =
            {
                .mq_mode = ETH_MQ_RX_NONE,
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
                .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
#else
                .max_rx_pkt_len = ETHER_MAX_LEN,
#endif /* RTE_VERSION */
            },
        // Disable multiple queues
        .txmode =
            {
                .mq_mode = ETH_MQ_TX_NONE,
            },
        // Enable loopback mode
        // .lpbk_mode = 1,
    };

    // Check port validity
    if (!rte_eth_dev_is_valid_port(port))
        return 0;

    // Query for device information
    rte_eth_dev_info_get(port, &device_info);

    // Check hardware capabilities
    if (NUM_TX_QUEUES > device_info.max_tx_queues)
        return 0;

    // Propagate supported TX offloads (fast message buffer release and
    // lock-free enqueue)
    port_conf.txmode.offloads =
        device_info.tx_offload_capa &
        (DEV_TX_OFFLOAD_MBUF_FAST_FREE | DEV_TX_OFFLOAD_MT_LOCKFREE);

    // Configure the device
    if (rte_eth_dev_configure(port, 0, NUM_TX_QUEUES, &port_conf))
        return 0;

    // Set the RX/TX queue sizes
    uint16_t tx_queue_size = RTE_MP_TX_DESC_DEFAULT;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &tx_queue_size, nullptr))
        return 0;

    // Set up TX queues
    for (uint16_t i = 0; i < NUM_TX_QUEUES; ++i) {
        if (rte_eth_tx_queue_setup(port, i, tx_queue_size,
                                   rte_eth_dev_socket_id(port), nullptr))
            return 0;
    }

    // Start the device
    if (rte_eth_dev_start(port))
        return 0;

    return device_info.tx_offload_capa & DEV_TX_OFFLOAD_MT_LOCKFREE ? 2 : 1;
}

bool TX::open() {
    // long num_procs = sysconf(_SC_NPROCESSORS_ONLN);
    // if (num_procs <= 0)
    //     return false;

    // Set the coremask to the number of available processors, excluding the
    // primary
    // unsigned mask = (1UL << static_cast<unsigned>(num_procs)) - 2;
    // std::stringstream mask_stream;
    // mask_stream << "0x" << std::hex << mask;
    // std::string str_mask = mask_stream.str();
    // DEFAULT_ARGV[3] = str_mask.data();

#ifndef HQ_INTERFACE_DPDK_SAME_PROCESS
    FILE *log = get_logfile();
    if (!log || rte_openlog_stream(log)) {
        fprintf(stderr, "Cannot open log file for DPDK TX!\n");
        return false;
    }

    if (rte_eal_init(DEFAULT_ARGC, DEFAULT_ARGV) == -1 ||
        rte_eal_process_type() != RTE_PROC_PRIMARY) {
        fprintf(stderr, "Cannot initialize DPDK Environment Abstraction Layer "
                        "(EAL) for TX!\n");
        return false;
    }
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */

    // Check for available devices
    if (!
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0)
        rte_eth_dev_count_avail()
#else
        rte_eth_dev_count()
#endif /* RTE_VERSION */
    ) {
        fprintf(stderr, "No available DPDK TX devices!\n");
        return false;
    }

    // Initialize packet buffer pool (send + cache)
    pool = rte_pktmbuf_pool_create(
        PKTMBUF_NAME,
        NUM_TX_QUEUES *
            (RTE_MP_TX_DESC_DEFAULT * (sizeof(PORT_IDS) / sizeof(*PORT_IDS))),
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool) {
        fprintf(stderr, "Cannot create DPDK memory pool '%s'!\n", PKTMBUF_NAME);
        return false;
    }

    for (unsigned i = 0; i < sizeof(PORT_IDS) / sizeof(*PORT_IDS); ++i) {
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
        char addr[RTE_ETHER_ADDR_FMT_SIZE];
#else
        char addr[ETHER_ADDR_FMT_SIZE];
#endif /* RTE_VERSION */
        char name[RTE_ETH_NAME_MAX_LEN];

        // Initialize port
        unsigned init = init_port(PORT_IDS[i]);
        if (!init) {
            fprintf(stderr, "Cannot initialize TX port %d!\n", PORT_IDS[i]);
            return false;
        }

        // Create software lock if hardware locking not supported
        if (init != 2)
            mutex.emplace();

        // Retrieve the MAC address and name
#if RTE_VERSION >= RTE_VERSION_NUM(19, 11, 0, 0)
        if (rte_eth_macaddr_get(PORT_IDS[i], &macs[i])) {
            fprintf(stderr, "Cannot get MAC address of TX port %d!\n",
                    PORT_IDS[i]);
            return false;
        }

        if (rte_eth_dev_get_name_by_port(PORT_IDS[i], name)) {
            fprintf(stderr, "Cannot get name of TX port %d!\n", PORT_IDS[i]);
            return false;
        }
#else
        rte_eth_macaddr_get(PORT_IDS[i], &macs[i]);
        rte_eth_dev_get_name_by_port(PORT_IDS[i], name);
#endif /* RTE_VERSION */
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
        rte_ether_format_addr(addr, sizeof(addr), &macs[i]);
#else
        ether_format_addr(addr, sizeof(addr), &macs[i]);
#endif /* RTE_VERSION */

        RTE_LOG(INFO, USER1,
                "Transmitting on port %d, name: %s, addr: %s, lcore: %u\n",
                PORT_IDS[i], name, addr, rte_lcore_id());
    }

    // Check all ports
    if (!check_ports(PORT_IDS, sizeof(PORT_IDS) / sizeof(*PORT_IDS))) {
        fprintf(stderr, "Link is not up for all TX ports!\n");
        return false;
    }

    return true;
}

bool TX::send_msg2(const enum hq_msg_op op, const uintptr_t pointer,
                   const uintptr_t value) {
    struct rte_mbuf *msg;
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
    struct rte_ether_hdr *ether;
#else
    struct ether_hdr *ether;
#endif /* RTE_VERSION */
    struct llc_hdr *llc;
    struct hq_msg *hq;
    bool ret = true;

    std::optional<std::scoped_lock<std::mutex>> lock;

#if !defined(NDEBUG)
    if (__builtin_expect(!*this, 0))
        return false;
#endif /* !NDEBUG */

    // Grab a new message
    msg = rte_pktmbuf_alloc(pool);
    if (__builtin_expect(!msg, 0)) {
        ret = false;
        goto out;
    }

    // Set the message metadata
    assert(msg->nb_segs == 1);
    msg->packet_type = RTE_PTYPE_L2_ETHER;
    msg->l2_len = sizeof(*ether) + sizeof(*llc);

    // Append the ethernet header
    ether = reinterpret_cast<decltype(ether)>(
        rte_pktmbuf_append(msg, sizeof(*ether)));
    if (__builtin_expect(!ether, 0)) {
        rte_pktmbuf_free(msg);
        ret = false;
        goto out;
    }
    ether->ether_type = htons(sizeof(*llc) + sizeof(*hq));
    // Set the destination MAC to the broadcast MAC
    memset(&ether->d_addr, -1, sizeof(ether->d_addr));

    // Append the LLC header
    llc =
        reinterpret_cast<decltype(llc)>(rte_pktmbuf_append(msg, sizeof(*llc)));
    if (__builtin_expect(!llc, 0)) {
        rte_pktmbuf_free(msg);
        ret = false;
        goto out;
    }
    llc->dsap = 0;
    llc->ssap = 0;
    llc->control = 0;

    // Append the actual message
    hq = reinterpret_cast<decltype(hq)>(rte_pktmbuf_append(msg, sizeof(*hq)));
    if (__builtin_expect(!hq, 0)) {
        rte_pktmbuf_free(msg);
        ret = false;
        goto out;
    }

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    hq->pid = pid;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
    hq->op = op;
    hq->values[0] = pointer;
    hq->values[1] = value;

    // Take the mutex if necessary
    if (mutex)
        lock.emplace(*mutex);

    assert(msg->pkt_len == msg->data_len &&
           msg->data_len == sizeof(*ether) + sizeof(*llc) + sizeof(*hq));
    for (unsigned i = 0; i < sizeof(PORT_IDS) / sizeof(*PORT_IDS); ++i) {
        // Overwrite the MAC for the current port
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
        rte_ether_addr_copy(&macs[i], &ether->s_addr);
#else
        ether_addr_copy(&macs[i], &ether->s_addr);
#endif /* RTE_VERSION */

        // Send the message
        if (rte_eth_tx_burst(PORT_IDS[i], NUM_TX_QUEUES - 1, &msg,
                             NUM_TX_PACKETS) != NUM_TX_PACKETS) {
            ret = false;
            goto out;
        }
    }

out:
    return ret;
}

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
bool TX::set_pid(pid_t p) {
    pid = p;
    return true;
}
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

} // namespace HQ::DPDK
