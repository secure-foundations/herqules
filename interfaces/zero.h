#ifndef _HQ_INTERFACES_ZERO_H_
#define _HQ_INTERFACES_ZERO_H_

#include <cstdint>
#include <ostream>
#include <utility>

#include <sys/mman.h>

#include "compat.h"
#include "config.h"
#include "fpga.h"
#include "intrinsics.h"
#include "messages.h"
#include "runtime.h"
#include "syscalls.h"

namespace HQ::ZERO {

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
        map = reinterpret_cast<uint8_t *>(mmap(
            NULL, MAP_SIZE, PROT_READ,
            MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_POPULATE, -1,
            0));
        return *this;
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
        return os << "ZERO::RX";
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
        if (this != &old) {
        }

        return *this;
    }

    ~TX() {
        if (*this)
            RAW_SYSCALL(2, SYS_munmap, MAP_ADDRESS, MAP_SIZE);
    }

    bool open() {
        map = reinterpret_cast<uint8_t *>(RAW_SYSCALL(
            6, SYS_mmap, MAP_ADDRESS, MAP_SIZE, PROT_WRITE,
            MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_POPULATE, -1,
            0));

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
            break;
        case CFI_MSG_CHECK:
            write64(MAP, REG_MSG2_CHECK, value);
            break;
        case CFI_MSG_CHECK_INVALIDATE:
            write64(MAP, REG_MSG2_CHECK_INVALIDATE, value);
            break;
        case HQ_MSG_INVALIDATE_BLOCK:
            write64(MAP, REG_MSG2_INVALIDATE_BLOCK, value);
            break;
        case HQ_MSG_COPY_BLOCK:
            write64(MAP, REG_MSG2_COPY_BLOCK, value);
            break;
        case HQ_MSG_MOVE_BLOCK:
            write64(MAP, REG_MSG2_MOVE_BLOCK, value);
            break;
        default:
#ifndef NDEBUG
            write64(MAP, REG_MSG0, op);
            write64(MAP, REG_MSG2, value);
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
            break;
        case HQ_MSG_INVALIDATE:
            write64(MAP, REG_MSG2_INVALIDATE, value);
            break;
        case HQ_MSG_SYSCALL:
            write64(MAP, REG_MSG2_SYSCALL, value);
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
        return true;
    }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    operator bool() const { return map == MAP; }
};

} // namespace HQ::ZERO

#endif /* _HQ_INTERFACES_ZERO_H_ */
