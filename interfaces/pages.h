#ifndef _HQ_INTERFACES_PAGES_H_
#define _HQ_INTERFACES_PAGES_H_

#include <cstdint>
#include <ostream>
#include <utility>

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "compat.h"
#include "config.h"
#include "fpga.h"
#include "intrinsics.h"
#include "messages.h"
#include "runtime.h"
#include "syscalls.h"

namespace HQ::PAGES {

static constexpr char PAGES_PATH[] = "/dev/pages-0";
static constexpr size_t MAP_SIZE = 0x2000ULL;

class RX {
    uint8_t *map = nullptr;
    struct hq_msg msg = {0};

  public:
    using const_iterator = const struct hq_msg *;

    RX() = default;

    RX(const RX &other) = delete;

    RX(RX &&old) { *this = std::move(old); }

    RX &operator=(RX &&old) {
        if (this != &old) {
        }

        return *this;
    }

    ~RX() {
        if (*this)
            munmap(map, MAP_SIZE);
    }

    bool open() {
        int fd = ::open(PAGES_PATH, O_CLOEXEC | O_SYNC | O_RDWR);
        if (fd <= 0)
            return false;

        map = reinterpret_cast<uint8_t *>(
            mmap(NULL, MAP_SIZE, PROT_READ,
                 MAP_FIXED | MAP_SHARED_VALIDATE | MAP_POPULATE, fd, 0));
        close(fd);

        return true;
    }

    const_iterator begin() { return &msg; }
    const_iterator get_msgs() {
        msg.pid = read64(map, REG_PID);
        msg.op = static_cast<enum hq_msg_op>(read64(map, REG_MSG0));
        msg.values[0] = read64(map, REG_MSG1);
        msg.values[1] = read64(map, REG_MSG2);
        return &msg + 1;
    }
    bool reset() { return false; }

    operator bool() const { return map && map != MAP_FAILED; }

    ssize_t get_drops() const { return read64(map, REG_MSG_DROPS); }

    friend std::ostream &operator<<(std::ostream &os, const RX &rx) {
        return os << "PAGES::RX";
    }
};

class TX {
    uint8_t *map = nullptr;

    static constexpr uintptr_t MAP_ADDRESS = 0x20000000ULL;
#define MAP reinterpret_cast<uint8_t *>(MAP_ADDRESS)

  public:
    TX() = default;

    TX(const TX &other) = delete;

    TX(TX &&old) { *this = std::move(old); }

    TX &operator=(TX &&old) {
        if (this != &old)
            map = old.map;

        return *this;
    }

    ~TX() {
        if (*this)
            RAW_SYSCALL(2, SYS_munmap, MAP_ADDRESS, MAP_SIZE);
    }

    bool open() {
        int fd =
            RAW_SYSCALL(3, SYS_open, reinterpret_cast<uintptr_t>(PAGES_PATH),
                        O_CLOEXEC | O_SYNC | O_RDWR, 0);
        if (fd <= 0)
            return false;

        map = reinterpret_cast<uint8_t *>(
            RAW_SYSCALL(6, SYS_mmap, MAP_ADDRESS, MAP_SIZE, PROT_WRITE,
                        MAP_FIXED | MAP_SHARED_VALIDATE | MAP_POPULATE, fd, 0));

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

        write64(MAP, REG_MSG1_ALIGN, pointer);

        switch (op) {
        case CFI_MSG_DEFINE:
            write64(MAP, REG_MSG2_DEFINE, value);
            flush512(MAP, REG_MSG2_DEFINE);
            break;
        case CFI_MSG_CHECK:
            write64(MAP, REG_MSG2_CHECK, value);
            flush512(MAP, REG_MSG2_CHECK);
            break;
        case CFI_MSG_CHECK_INVALIDATE:
            write64(MAP, REG_MSG2_CHECK_INVALIDATE, value);
            flush512(MAP, REG_MSG2_CHECK_INVALIDATE);
            break;
        case HQ_MSG_INVALIDATE_BLOCK:
            write64(MAP, REG_MSG2_INVALIDATE_BLOCK, value);
            flush512(MAP, REG_MSG2_INVALIDATE_BLOCK);
            break;
        case HQ_MSG_COPY_BLOCK:
            write64(MAP, REG_MSG2_COPY_BLOCK, value);
            flush512(MAP, REG_MSG2_COPY_BLOCK);
            break;
        case HQ_MSG_MOVE_BLOCK:
            write64(MAP, REG_MSG2_MOVE_BLOCK, value);
            flush512(MAP, REG_MSG2_MOVE_BLOCK);
            break;
        default:
#ifndef NDEBUG
            write64(MAP, REG_MSG0, op);
            write64(MAP, REG_MSG2, value);
            flush512(MAP, REG_MSG2_CHECK);
#else
            return false;
#endif /* !NDEBUG */
            break;
        }

        // write256(MAP, REG_MSG0, fill256(op, pointer, value, 0));

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
            write64(MAP, REG_MSG2_INIT_GLOBALS, value);
            flush512(MAP, REG_MSG2_INIT_GLOBALS);
            break;
        case HQ_MSG_INVALIDATE:
            write64(MAP, REG_MSG2_INVALIDATE, value);
            flush512(MAP, REG_MSG2_INVALIDATE);
            break;
        case HQ_MSG_SYSCALL:
            write64(MAP, REG_MSG2_SYSCALL, value);
            flush512(MAP, REG_MSG2_SYSCALL);
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

        write64(MAP, REG_PID, pid);
        flush512(MAP, REG_PID);
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

    operator bool() const { return map == MAP; }
};

} // namespace HQ::PAGES

#endif /* _HQ_INTERFACES_PAGES_H_ */
