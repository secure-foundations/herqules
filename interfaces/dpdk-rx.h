#ifndef _HQ_INTERFACES_DPDK_RX_H_
#define _HQ_INTERFACES_DPDK_RX_H_

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <iterator>
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

namespace HQ::DPDK {

class RX {
    // Default arguments for DPDK
    inline static char ARG_VERIFIER[] = "verifier";
    // inline static char ARG_COREMASK_PRIMARY[] = "0x01";
    inline static char ARG_PREFIX[] = "--file-prefix=rx";
#ifndef HQ_INTERFACE_DPDK_SAME_PROCESS
    inline static char ARG_BLACKLIST_PCI[] = "0000:13:00.0";
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */
    inline static char *DEFAULT_ARGV[] = {ARG_VERIFIER,     ARG_PRIMARY,
#ifndef HQ_INTERFACE_DPDK_SAME_PROCESS
                                          ARG_PREFIX,       ARG_MEMORY,
                                          ARG_MEMORY_1GB,   ARG_BLACKLIST,
                                          ARG_BLACKLIST_PCI
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */
    };
    static constexpr size_t BUFFER_SIZE =
        HQ_INTERFACE_APPLICATION_SIZE / sizeof(struct hq_msg);
    static constexpr unsigned DEFAULT_ARGC =
        sizeof(DEFAULT_ARGV) / sizeof(*DEFAULT_ARGV);

    static constexpr char PKTMBUF_NAME[] = "HQ_PACKET_POOL_RX";

#ifdef HQ_INTERFACE_DPDK_SAME_PROCESS
  public:
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */
    static constexpr uint16_t PORT_IDS[] = {0};
#ifdef HQ_INTERFACE_DPDK_SAME_PROCESS
  private:
#endif /* HQ_INTERFACE_DPDK_SAME_PROCESS */

    struct rte_mempool *pool = nullptr;
    std::array<struct rte_mbuf *, BUFFER_SIZE> msgs;
    size_t read = 0;

#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
    std::array<struct rte_ether_addr, sizeof(PORT_IDS) / sizeof(*PORT_IDS)>
        macs;
#else
    std::array<struct ether_addr, sizeof(PORT_IDS) / sizeof(*PORT_IDS)> macs;
#endif /* RTE_VERSION */

    bool init_port(uint16_t port);

  public:
    // Must use custom iterator for subfield access
    template <typename T, typename U> class iterator {
        using internal_pointer = U;

      public:
        using difference_type = std::ptrdiff_t;
        using pointer = T *;
        using reference = T &;
        using value_type = T;
        using iterator_category = std::random_access_iterator_tag;

        iterator(std::nullptr_t) {}
        iterator(internal_pointer _ptr) : ptr(_ptr) {}
        iterator(const iterator &other) : ptr(other.ptr) {}
        iterator(iterator &&old) { *this = std::move(old); }

        iterator &operator=(iterator &&old) {
            if (this != &old) {
                ptr = old.ptr;
                old.ptr = nullptr;
            }

            return *this;
        }

        iterator &operator++() {
            ++ptr;
            return *this;
        }
        iterator operator++(int offset) {
            iterator result(*this);
            ++(*this);
            return result;
        }

        iterator operator+=(difference_type n) { ptr += n; }
        iterator operator+(difference_type n) const {
            iterator result(*this);
            result += n;
            return result;
        }

        iterator &operator--() {
            --ptr;
            return *this;
        }
        iterator operator--(int offset) {
            iterator result(*this);
            --(*this);
            return result;
        }

        iterator operator-=(difference_type n) { ptr -= n; }
        iterator operator-(difference_type n) const {
            iterator result(*this);
            result -= n;
            return result;
        }

        difference_type operator-(iterator &other) const {
            return ptr - other.ptr;
        }

        reference operator*() const {
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
            return *rte_pktmbuf_mtod_offset(*ptr, struct hq_msg *,
                                            sizeof(struct rte_ether_hdr) +
                                                sizeof(struct llc_hdr));
#else
            return *rte_pktmbuf_mtod_offset(*ptr, struct hq_msg *,
                                            sizeof(struct ether_hdr) +
                                                sizeof(struct llc_hdr));
#endif /* RTE_VERSION */
        }
        pointer operator->() const {
#if RTE_VERSION >= RTE_VERSION_NUM(19, 8, 0, 0)
            return rte_pktmbuf_mtod_offset(*ptr, struct hq_msg *,
                                           sizeof(struct rte_ether_hdr) +
                                               sizeof(struct llc_hdr));
#else
            return rte_pktmbuf_mtod_offset(*ptr, struct hq_msg *,
                                           sizeof(struct ether_hdr) +
                                               sizeof(struct llc_hdr));
#endif /* RTE_VERSION */
        }

        operator bool() const { return ptr; }
        bool operator==(const iterator &other) const {
            return ptr == other.ptr;
        }
        bool operator!=(const iterator &other) const {
            return !(*this == other);
        }
        bool operator>(const iterator &other) const { return ptr > other.ptr; }
        bool operator<(const iterator &other) const { return ptr < other.ptr; }

      private:
        internal_pointer ptr = nullptr;
    };

    using const_iterator =
        iterator<const struct hq_msg, const struct rte_mbuf *const *>;

    RX() = default;

    RX(const RX &other) = delete;

    RX(RX &&old) { *this = std::move(old); }

    RX &operator=(RX &&old) {
        if (this != &old) {
            if (read) {
#if RTE_VERSION >= RTE_VERSION_NUM(19, 11, 0, 0)
                rte_pktmbuf_free_bulk(msgs.data(), read);
#else
                unsigned i = 0;
                while (i < read)
                    rte_pktmbuf_free(msgs[i++]);
#endif /* RTE_VERSION */
            }

            pool = old.pool;
            msgs = std::move(old.msgs);
            read = old.read;
            macs = std::move(old.macs);

            old.pool = nullptr;
            old.read = 0;
        }

        return *this;
    }

    ~RX() {
        if (!pool)
            return;

        for (unsigned i = 0; i < sizeof(PORT_IDS) / sizeof(*PORT_IDS); ++i) {
            rte_eth_dev_stop(PORT_IDS[i]);
            rte_eth_dev_close(PORT_IDS[i]);
        }

        rte_mempool_free(pool);

#if RTE_VERSION >= RTE_VERSION_NUM(18, 2, 0, 0)
        rte_eal_cleanup();
#endif /* RTE_VERSION */
    }

    bool open();
    const_iterator begin() { return const_iterator(&msgs[0]); }
    const_iterator get_msgs();
    bool reset() { return false; }

    friend std::ostream &operator<<(std::ostream &os, const RX &rx);
};

} // namespace HQ::DPDK

#endif /* _HQ_INTERFACES_DPDK_RX_H_ */
