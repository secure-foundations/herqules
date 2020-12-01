#include "dpdk-rx.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <sstream>

#include <arpa/inet.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <unistd.h>

namespace HQ::DPDK {

static FILE *get_logfile() {
    std::stringstream path;
    path << DPDK_LOG_PATH << "." << getpid() <<
#ifndef HQ_INTERFACE_DPDK_SAME_PROCESS
        ".rx.log"
#else
        ".both.log"
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */
        ;
    const std::string &str = path.str();
    return fopen(str.c_str(), "w");
}

bool RX::init_port(uint16_t port) {
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
        return false;

    // Configure the device
    if (rte_eth_dev_configure(port, NUM_RX_QUEUES, 0, &port_conf))
        return false;

    // Set the RX/TX queue sizes
    uint16_t rx_queue_size = RTE_MP_RX_DESC_DEFAULT;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, nullptr, &rx_queue_size))
        return false;

    // Set up RX queues
    for (uint16_t i = 0; i < NUM_RX_QUEUES; ++i) {
        if (rte_eth_rx_queue_setup(port, i, rx_queue_size,
                                   rte_eth_dev_socket_id(port), nullptr, pool))
            return false;
    }

    // Enable promiscuous mode
#if RTE_VERSION >= RTE_VERSION_NUM(19, 11, 0, 0)
    if (rte_eth_promiscuous_enable(port))
        return false;
#else
    rte_eth_promiscuous_enable(port);
#endif /* RTE_VERSION */

    // Start the device
    if (rte_eth_dev_start(port))
        return false;

    return true;
}

bool RX::open() {
    FILE *log = get_logfile();
    if (!log || rte_openlog_stream(log)) {
        std::cerr << "Cannot open log file for DPDK RX!" << std::endl;
        return false;
    }

    if (rte_eal_init(DEFAULT_ARGC, DEFAULT_ARGV) == -1 ||
        rte_eal_process_type() != RTE_PROC_PRIMARY) {
        std::cerr << "Cannot initialize DPDK Environment Abstraction Layer "
                     "(EAL) for RX!"
                  << std::endl;
        return false;
    }

    // Check for available devices
    if (!
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0)
        rte_eth_dev_count_avail()
#else
        rte_eth_dev_count()
#endif /* RTE_VERSION */
    ) {
        std::cerr << "No available DPDK RX devices!" << std::endl;
        return false;
    }

    // Initialize packet buffer pool (receive + cache)
    pool = rte_pktmbuf_pool_create(
        PKTMBUF_NAME,
        NUM_RX_QUEUES *
            (RTE_MP_RX_DESC_DEFAULT * (sizeof(PORT_IDS) / sizeof(*PORT_IDS))),
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool) {
        std::cerr << "Cannot create DPDK memory pool '" << PKTMBUF_NAME << "'!"
                  << std::endl;
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
        if (!init_port(PORT_IDS[i])) {
            std::cerr << "Cannot initialize RX port " << PORT_IDS[i] << "!"
                      << std::endl;
            return false;
        }

        // Retrieve the MAC address and name
#if RTE_VERSION >= RTE_VERSION_NUM(19, 11, 0, 0)
        if (rte_eth_macaddr_get(PORT_IDS[i], &macs[i])) {
            std::cerr << "Cannot get MAC address of RX port " << PORT_IDS[i]
                      << "!" << std::endl;
            return false;
        }

        if (rte_eth_dev_get_name_by_port(PORT_IDS[i], name)) {
            std::cerr << "Cannot get name of RX port " << PORT_IDS[i] << "!"
                      << std::endl;
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
                "Receiving on port %d, name: %s, addr: %s, lcore: %u\n",
                PORT_IDS[i], name, addr, rte_lcore_id());
    }

    // Check all ports
    if (!check_ports(PORT_IDS, sizeof(PORT_IDS) / sizeof(*PORT_IDS))) {
        fprintf(stderr, "Link is not up for all RX ports!\n");
        return false;
    }

    return true;
}

RX::const_iterator RX::get_msgs() {
#ifndef NDEBUG
    if (__builtin_expect(!pool, 0))
        return nullptr;
#endif /* !NDEBUG */

    if (read) {
#if RTE_VERSION >= RTE_VERSION_NUM(19, 11, 0, 0)
        rte_pktmbuf_free_bulk(msgs.data(), read);
#else
        unsigned i = 0;
        while (i < read)
            rte_pktmbuf_free(msgs[i++]);
#endif /* RTE_VERSION */
        read = 0;
    }

    for (unsigned i = 0; i < sizeof(PORT_IDS) / sizeof(*PORT_IDS); ++i) {
        unsigned sz =
            rte_eth_rx_burst(PORT_IDS[i], NUM_RX_QUEUES - 1, &msgs[read],
                             std::min(msgs.size() - read,
                                      static_cast<unsigned long>(UINT16_MAX)));

        for (unsigned j = 0; j < sz; ++j) {
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
            struct rte_ether_hdr *ether;
#else
            struct ether_hdr *ether;
#endif /* RTE_VERSION */
            struct llc_hdr *llc;
            assert(rte_pktmbuf_is_contiguous(msgs[j]));

            // Ethernet has a minimum frame length of RTE_ETHER_MIN_LEN
            assert(rte_pktmbuf_pkt_len(msgs[j]) >=
                   sizeof(*ether) + sizeof(*llc) + sizeof(struct hq_msg));

            // Check the packet headers
            ether = rte_pktmbuf_mtod_offset(msgs[j], decltype(ether), 0);
            llc =
                rte_pktmbuf_mtod_offset(msgs[j], decltype(llc), sizeof(*ether));
            if (
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
                (rte_is_broadcast_ether_addr(&ether->d_addr) ||
                 rte_is_same_ether_addr(&ether->d_addr, &macs[i]))
#else
                (is_broadcast_ether_addr(&ether->d_addr) ||
                 is_same_ether_addr(&ether->d_addr, &macs[i]))
#endif /* RTE_VERSION */
                && !llc->dsap && !llc->ssap && !llc->control) {
                // Store the actual message
                msgs[read++] = msgs[j];
            } else {
#ifndef NDEBUG
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
                char src_addr[RTE_ETHER_ADDR_FMT_SIZE],
                    dst_addr[RTE_ETHER_ADDR_FMT_SIZE];
                rte_ether_format_addr(src_addr, sizeof(src_addr),
                                      &ether->s_addr);
                rte_ether_format_addr(dst_addr, sizeof(dst_addr),
                                      &ether->d_addr);
#else  /* RTE_VERSION */
                char src_addr[ETHER_ADDR_FMT_SIZE],
                    dst_addr[ETHER_ADDR_FMT_SIZE];
                ether_format_addr(src_addr, sizeof(src_addr), &ether->s_addr);
                ether_format_addr(dst_addr, sizeof(dst_addr), &ether->d_addr);
#endif /* RTE_VERSION */
                std::cout << "Unexpected packet: ether.src " << src_addr
                          << ", ether.dst " << dst_addr << ", llc.dsap "
                          << llc->dsap << ", llc.ssap " << llc->ssap
                          << ", llc.control " << llc->control << "!"
                          << std::endl;
#endif /* NDEBUG */

                rte_pktmbuf_free(msgs[j]);
            }
        }
    }

    return const_iterator(&msgs[read]);
}

std::ostream &operator<<(std::ostream &os, const RX &rx) {
    return os << "DPDK::RX = Pool: " << rx.pool;
}

} // namespace HQ::DPDK
