#ifndef _HQ_INTERFACES_OPAE_TX_H_
#define _HQ_INTERFACES_OPAE_TX_H_

#include <cstdint>
#include <utility>

#include <fcntl.h>
#include <linux/version.h>
#include <sys/mman.h>

#include "compat.h"
#include "config.h"
#include "fpga.h"
#include "intrinsics.h"
#include "messages.h"
#include "runtime.h"
#include "syscalls.h"

namespace HQ::OPAE {

class TX {
// Either use the upstream kernel driver (dfl-afu, etc) or the old Intel driver
// from the opae-intel-fpga-driver package (intel-fpga-afu, etc)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/fpga-dfl.h>
    using fpga_port_info_t = struct dfl_fpga_port_region_info;
    static constexpr auto GET_REGION_INFO = DFL_FPGA_PORT_GET_REGION_INFO;
    static constexpr auto REGION_INDEX_AFU = DFL_PORT_REGION_INDEX_AFU;
    static constexpr auto MASK_WRITE_MMAP =
        DFL_PORT_REGION_WRITE | DFL_PORT_REGION_MMAP;
#else
#include <linux/intel-fpga.h>
#include <linux/ioctl.h>
    using fpga_port_info_t = struct fpga_port_region_info;
    static constexpr auto GET_REGION_INFO = FPGA_PORT_GET_REGION_INFO;
    static constexpr auto REGION_INDEX_AFU = FPGA_PORT_INDEX_UAFU;
    static constexpr auto MASK_WRITE_MMAP =
        FPGA_REGION_WRITE | FPGA_REGION_MMAP;
#endif /* LINUX_VERSION_CODE */

    static constexpr uintptr_t MMIO_ADDRESS = 0x20000000ULL;

#define MMIO reinterpret_cast<volatile uint8_t *>(MMIO_ADDRESS)

    uint8_t *mmio = nullptr;

  public:
    TX() = default;

    TX(const TX &other) = delete;

    TX(TX &&old) { *this = std::move(old); }

    TX &operator=(TX &&old) {
        if (this != &old)
            mmio = old.mmio;

        return *this;
    }

    ~TX() {
        if (*this)
            RAW_SYSCALL(2, SYS_munmap, MMIO_ADDRESS, FPGA_MMIO_SIZE);
    }

    bool open() {
        // Must be O_RDWR (instead of O_WRONLY) to mmap with MAP_SHARED |
        // PROT_WRITE
        int fd =
            RAW_SYSCALL(3, SYS_open, reinterpret_cast<uintptr_t>(FPGA_PATH),
                        O_CLOEXEC | O_SYNC | O_RDWR, 0);
        if (fd <= 0)
            return false;

        fpga_port_info_t info = {
            .argsz = sizeof(info),
            .flags = 0,
            .index = REGION_INDEX_AFU,
            .padding = 0,
        };

        if (RAW_SYSCALL(3, SYS_ioctl, fd, GET_REGION_INFO,
                        reinterpret_cast<uintptr_t>(&info)) ||
            (info.flags & MASK_WRITE_MMAP) != MASK_WRITE_MMAP)
            goto out;

        if (info.size != FPGA_MMIO_SIZE)
            goto out;

        // FIXME: Prevent mapping of the entire device
        mmio = reinterpret_cast<uint8_t *>(RAW_SYSCALL(
            6, SYS_mmap, MMIO_ADDRESS, FPGA_MMIO_SIZE, PROT_WRITE,
            MAP_FIXED | MAP_SHARED_VALIDATE | MAP_POPULATE, fd, info.offset));

    out:
        RAW_SYSCALL(1, SYS_close, fd);
        return *this;
    }

    inline bool send_msg2(const enum hq_msg_op op, const uintptr_t pointer,
                          const uintptr_t value) {
#ifndef NDEBUG
        if (__builtin_expect(!*this, 0))
            return false;
#endif /* !NDEBUG */

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
        PID_SEND_FUNCTION();
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

        write64(MMIO, REG_MSG1_ALIGN, pointer);

        switch (op) {
        case CFI_MSG_DEFINE:
            write64(MMIO, REG_MSG2_DEFINE, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2_DEFINE);
#endif /* HQ_INTERFACE_OPAE_WC */
            break;
        case CFI_MSG_CHECK:
            write64(MMIO, REG_MSG2_CHECK, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2_CHECK);
#endif /* HQ_INTERFACE_OPAE_WC */
            break;
        case CFI_MSG_CHECK_INVALIDATE:
            write64(MMIO, REG_MSG2_CHECK_INVALIDATE, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2_CHECK_INVALIDATE);
#endif /* HQ_INTERFACE_OPAE_WC */
            break;
        case HQ_MSG_INVALIDATE_BLOCK:
            write64(MMIO, REG_MSG2_INVALIDATE_BLOCK, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2_INVALIDATE_BLOCK);
#endif /* HQ_INTERFACE_OPAE_WC */
            break;
        case HQ_MSG_COPY_BLOCK:
            write64(MMIO, REG_MSG2_COPY_BLOCK, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2_COPY_BLOCK);
#endif /* HQ_INTERFACE_OPAE_WC */
            break;
        case HQ_MSG_MOVE_BLOCK:
            write64(MMIO, REG_MSG2_MOVE_BLOCK, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2_MOVE_BLOCK);
#endif /* HQ_INTERFACE_OPAE_WC */
            break;
        default:
#ifndef NDEBUG
            write64(MMIO, REG_MSG0, op);
            write64(MMIO, REG_MSG2, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2);
#endif /* HQ_INTERFACE_OPAE_WC */
#else
            return false;
#endif /* !NDEBUG */
            break;
        }

        return true;
    }

    inline bool send_msg1(const enum hq_msg_op op, const uintptr_t value) {
#ifndef NDEBUG
        if (__builtin_expect(!*this, 0))
            return false;
#endif /* !NDEBUG */

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
        PID_SEND_FUNCTION();
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

        switch (op) {
        case CFI_MSG_INIT_GLOBALS:
            write64(MMIO, REG_MSG2_INIT_GLOBALS, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2_INIT_GLOBALS);
#endif /* HQ_INTERFACE_OPAE_WC */
            break;
        case HQ_MSG_INVALIDATE:
            write64(MMIO, REG_MSG2_INVALIDATE, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2_INVALIDATE);
#endif /* HQ_INTERFACE_OPAE_WC */
            break;
        case HQ_MSG_SYSCALL:
            write64(MMIO, REG_MSG2_SYSCALL, value);
#ifdef HQ_INTERFACE_OPAE_WC
            flush512(MMIO, REG_MSG2_SYSCALL);
#endif /* HQ_INTERFACE_OPAE_WC */
            /* See note below about weakly-ordered stores. Although syscall is
             * not explicitly listed as a serializing instruction, it is stated
             * that instructions after a syscall will not be executed until all
             * instructions before a syscall have completed execution. Since it
             * does not make sense to reorder instructions across privilege
             * levels, an explicit sfence should not be necessary here. */
            break;
        default:
            return false;
            break;
        }

        return true;
    }

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    bool set_pid(pid_t pid) {
#ifndef NDEBUG
        if (__builtin_expect(!*this, 0))
            return false;
#endif /* !NDEBUG */

        write64(MMIO, REG_PID, pid);
#ifdef HQ_INTERFACE_OPAE_WC
        flush512(MAP, REG_PID);
#endif /* HQ_INTERFACE_OPAE_WC */
#if defined(__CLWB__) || defined(__CLFLUSHOPT__)
        /* With weakly-ordered stores (non-temporal/write-combining), reordering
         * may occur with occur other instructions. Specifically, both clwb and
         * clflushopt may be reordered with respect to stores or clwb/clflushopt
         * to other cachelines. Since userspace does not know if the underlying
         * memory page is write combining, always insert explicit ordering. */
        sfence();
#endif /* __CLWB__ || __CLFLUSHOPT__ */
        return true;
    }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    operator bool() const { return mmio == MMIO; }
};

} // namespace HQ::OPAE

#endif /* _HQ_INTERFACES_OPAE_TX_H_ */
