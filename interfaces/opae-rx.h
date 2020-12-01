#ifndef _HQ_INTERFACES_OPAE_RX_H_
#define _HQ_INTERFACES_OPAE_RX_H_

#include <array>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <type_traits>

#include <opae/cxx/core/handle.h>
#include <opae/cxx/core/shared_buffer.h>

#include "fpga.h"
#include "intrinsics.h"
#include "messages.h"

namespace HQ::OPAE {

using buffer_t = opae::fpga::types::shared_buffer::ptr_t;
using fpga_t = opae::fpga::types::handle::ptr_t;

class RX {
    static constexpr fpga_guid FPGA_GUID = {AFU_UUID};
    // To ensure page continuity, OPAE will allocate either a 4KB page, 2MB
    // hugepage, or 1GB hugepage. Since 4KB is too small, request a full 2MB
    // page.
    static constexpr size_t BUFFER_SIZE =
        HQ_INTERFACE_APPLICATION_SIZE / sizeof(struct fpga_msg);
    static constexpr unsigned DEFAULT_CSR_SPACE = 0;

    fpga_t fpga;
    buffer_t buffer;
    size_t read = 0;
    volatile uint8_t *mmio = nullptr;

    static fpga_t open_device();

  public:
    // Must use custom iterator for circular buffer, subfield access, and
    // counter checking
    template <typename T, typename U, size_t SZ> class iterator {
        using internal_pointer = U;

      public:
        using difference_type = std::ptrdiff_t;
        // FIXME: Casting away volatile for underlying buffer
        using pointer = T *;
        using reference = T &;
        using value_type = T;
        using iterator_category = std::forward_iterator_tag;

        iterator(std::nullptr_t) : base(nullptr), read(nullptr) {}
        iterator(internal_pointer _ptr, internal_pointer _base, size_t *_read)
            : ptr(_ptr), base(_base), read(_read) {}
        iterator(const iterator &other) = delete;
        iterator(iterator &&old) : base(old.base), read(old.read) {
            *this = std::move(old);
        }

        iterator &operator=(const iterator &old) {
            if (this != &old) {
                assert(base == old.base && sz == old.sz);

                ptr = old.ptr;
            }

            return *this;
        }

        iterator &operator=(iterator &&old) {
            if (this != &old) {
                assert(base == old.base && sz == old.sz);

                ptr = old.ptr;
                old.ptr = nullptr;
            }

            return *this;
        }

        iterator &operator++() {
            if (__builtin_expect(++ptr >= base + SZ, 0))
                ptr -= SZ;

            ++(*read);
            return *this;
        }

        // FIXME: Shared buffer could be overwritten by FPGA before dereference
        reference operator*() const { return ptr->msg; }
        pointer operator->() const { return &ptr->msg; }

        operator bool() const { return true; }
        bool is_valid() const { return ptr->counter == *read + 1; }
        bool operator==(const iterator &other) const {
            return ptr == other.ptr
#ifndef NDEBUG
                   && base == other.base && read == other.read && sz == other.sz
#endif /* NDEBUG */
                ;
        }
        bool operator!=(const iterator &other) const {
            return !(*this == other);
        }
        bool operator>(const iterator &other) const { return ptr > other.ptr; }
        bool operator<(const iterator &other) const { return ptr < other.ptr; }

      private:
        internal_pointer ptr = nullptr;
        const internal_pointer base;
        size_t *const read = nullptr;
        const size_t sz = SZ;
    };

    using const_iterator =
        iterator<const volatile struct hq_msg, const volatile struct fpga_msg *,
                 BUFFER_SIZE>;

    RX() = default;

    RX(const RX &other) = delete;

    RX(RX &&old) { *this = std::move(old); }

    RX &operator=(RX &&old) {
        if (this != &old) {
            fpga = std::move(old.fpga);
            buffer = std::move(old.buffer);
            read = old.read;
            mmio = old.mmio;

            old.mmio = nullptr;
            old.read = 0;
        }

        return *this;
    }

    ~RX() {
        if (*this) {
#ifdef HQ_INTERFACE_OPAE_SIMULATE
            fpga->write_csr64(REG_HOST_BUF_ADDR, 0);
#else
            write64(mmio, REG_HOST_BUF_ADDR, 0);
#endif /* HQ_INTERFACE_OPAE_SIMULATE */
        }
    }

    bool open();
    const_iterator begin() {
        const auto *buf =
            reinterpret_cast<volatile struct fpga_msg *>(buffer->c_type());
        return const_iterator(&buf[read % BUFFER_SIZE], buf, &read);
    }
    const_iterator get_msgs();
    bool reset();

    operator bool() const { return fpga && buffer && mmio; }

    ssize_t get_drops() const;

    friend std::ostream &operator<<(std::ostream &os, const RX &rx);
};

} // namespace HQ::OPAE

#endif /* _HQ_INTERFACES_OPAE_RX_H_ */
