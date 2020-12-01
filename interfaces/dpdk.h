#ifndef _HQ_INTERFACES_DPDK_H_
#define _HQ_INTERFACES_DPDK_H_

#include <rte_cycles.h>

#include "config.h"

namespace HQ::DPDK {

struct alignas(4) llc_hdr {
    uint8_t dsap;
    uint8_t ssap;
    uint16_t control;
};

#ifndef HQ_INTERFACE_DPDK_SAME_PROCESS
// inline static char ARG_COREMASK[] = "-c";
inline static char ARG_BLACKLIST[] = "-b";
inline static char ARG_MEMORY[] = "-m";
inline static char ARG_MEMORY_1GB[] = "1024";
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */
inline static char ARG_PRIMARY[] = "--proc-type=primary";

static constexpr char DPDK_LOG_PATH[] = "/tmp/dpdk";

static constexpr uint16_t NUM_RX_QUEUES = 1;
static constexpr uint16_t NUM_TX_QUEUES = 1;

static constexpr unsigned PORT_CHECK_INTERVAL = 100;
static constexpr unsigned PORT_NUM_CHECKS_MAX = 90;

static constexpr unsigned MBUF_CACHE_SIZE = 32;
#if RTE_VERSION >= RTE_VERSION_NUM(19, 11, 0, 0)
static constexpr uint16_t RTE_MP_RX_DESC_DEFAULT =
    std::min(HQ_INTERFACE_APPLICATION_SIZE / RTE_ETHER_MIN_LEN, UINT16_MAX);
#else
static constexpr uint16_t RTE_MP_RX_DESC_DEFAULT =
    std::min(HQ_INTERFACE_APPLICATION_SIZE / ETHER_MIN_LEN, UINT16_MAX);
#endif
static constexpr uint16_t RTE_MP_TX_DESC_DEFAULT = 512;

inline bool check_ports(const uint16_t *ports, size_t num_ports) {
    bool all_ports_up;
    struct rte_eth_link link;

    for (unsigned i = 0; i <= PORT_NUM_CHECKS_MAX; ++i) {
        all_ports_up = true;

        for (unsigned i = 0; i < num_ports; ++i) {
#if RTE_VERSION >= RTE_VERSION_NUM(19, 11, 0, 0)
            if (rte_eth_link_get_nowait(ports[i], &link) < 0) {
                all_ports_up = false;
                continue;
            }
#else
            rte_eth_link_get_nowait(ports[i], &link);
#endif

            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = false;
                break;
            }
        }

        if (all_ports_up)
            break;
        rte_delay_ms(PORT_CHECK_INTERVAL);
    }

    return all_ports_up;
}

} // namespace HQ::DPDK

#endif /* _HQ_INTERFACES_DPDK_H_ */
