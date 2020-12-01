#ifndef _HQ_INTERFACES_DPDK_TX_H_
#define _HQ_INTERFACES_DPDK_TX_H_

#include <array>
#include <cassert>
#include <cstdint>
#include <mutex>
#include <optional>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_version.h>

#include "dpdk.h"
#include "messages.h"

#ifdef HQ_INTERFACE_DPDK_SAME_PROCESS
#include "dpdk-rx.h"
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */

namespace HQ::DPDK {

class TX {
    // Default arguments for DPDK
#ifndef HQ_INTERFACE_DPDK_SAME_PROCESS
    inline static char ARG_APPLICATION[] = "application";
    inline static char ARG_PREFIX[] = "--file-prefix=tx";
    inline static char ARG_BLACKLIST_PCI[] = "0000:0b:00.0";
    inline static char *DEFAULT_ARGV[] = {
        ARG_APPLICATION, ARG_PRIMARY,   ARG_PREFIX,       ARG_MEMORY,
        ARG_MEMORY_1GB,  ARG_BLACKLIST, ARG_BLACKLIST_PCI};
    static constexpr unsigned DEFAULT_ARGC =
        sizeof(DEFAULT_ARGV) / sizeof(*DEFAULT_ARGV);
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */

    static constexpr char PKTMBUF_NAME[] = "HQ_PACKET_POOL_TX";

    static constexpr char MALLOC_NAME[] = "HQ_MSG_BUFFER";

    static constexpr unsigned NUM_TX_PACKETS = 1;

#ifndef HQ_INTERFACE_DPDK_SAME_PROCESS
    static constexpr uint16_t PORT_IDS[] = {0};
#else
    static constexpr uint16_t PORT_IDS[] = {
        (sizeof(RX::PORT_IDS) / sizeof(*RX::PORT_IDS)) + 0};
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    pid_t pid = -1;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
    struct rte_mempool *pool = nullptr;
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
    std::array<struct rte_ether_addr, sizeof(PORT_IDS) / sizeof(*PORT_IDS)>
        macs;
#else
    std::array<struct ether_addr, sizeof(PORT_IDS) / sizeof(*PORT_IDS)> macs;
#endif /* RTE_VERSION */
    std::optional<std::mutex> mutex;

    unsigned init_port(uint16_t port);
    static void error_callback(struct rte_mbuf **unsent, uint16_t count,
                               void *data);

  public:
    TX() = default;

    TX(const TX &other) = delete;

    TX(TX &&old) { *this = std::move(old); }

    TX &operator=(TX &&old) {
        if (this != &old) {
            std::mutex dummy;
            std::optional<std::scoped_lock<std::mutex, std::mutex>> lock;
            if (old.mutex && mutex)
                lock.emplace(*old.mutex, *mutex);
            else if (old.mutex)
                lock.emplace(*old.mutex, dummy);
            else if (mutex)
                lock.emplace(*mutex, dummy);

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
            pid = old.pid;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
            pool = old.pool;
            old.pool = nullptr;

            macs = std::move(old.macs);
        }

        return *this;
    }

    ~TX() {
        std::optional<std::scoped_lock<std::mutex>> lock;

        if (!*this)
            return;

        if (mutex)
            lock.emplace(*mutex);

#if RTE_VERSION >= RTE_VERSION_NUM(18, 2, 0, 0)
        rte_eal_cleanup();
#endif /* RTE_VERSION */
    }

    bool open();
    bool send_msg2(const enum hq_msg_op op, const uintptr_t pointer,
                   const uintptr_t value);
    inline bool send_msg1(const enum hq_msg_op op, const uintptr_t value) {
        return send_msg2(op, 0, value);
    }

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    bool set_pid(pid_t pid);
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    operator bool() const { return pool; }
};

} // namespace HQ::DPDK

#endif /* _HQ_INTERFACES_DPDK_TX_H_ */
