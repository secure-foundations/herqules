#ifndef _HQ_INTERFACES_POSIX_FIFO_H_
#define _HQ_INTERFACES_POSIX_FIFO_H_

#include <array>
#include <cstdint>
#include <ostream>

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "messages.h"
#include "syscalls.h"

// Reads will block until data is available, and writes will block if underlying
// buffer is full
namespace HQ::POSIX_FIFO {

static constexpr size_t BUFFER_SIZE =
    HQ_INTERFACE_APPLICATION_SIZE / sizeof(struct hq_msg);
static constexpr char FIFO_PATH[] = "/tmp/HQ";

class RX {
    int fd = -1;
    std::array<struct hq_msg, BUFFER_SIZE> msgs;
    size_t read = 0;

  public:
    using const_iterator = decltype(msgs)::const_iterator;

    RX() = default;

    RX(const RX &other) = delete;

    RX(RX &&old) { *this = std::move(old); }

    RX &operator=(RX &&old) {
        if (this != &old) {
            if (*this)
                close(fd);

            fd = old.fd;
            msgs = std::move(old.msgs);
            read = old.read;

            old.fd = -1;
            old.read = 0;
        }

        return *this;
    }

    ~RX() {
        if (*this) {
            close(fd);
            unlink(FIFO_PATH);
        }
    }

    bool open();
    const_iterator begin() { return &msgs[0]; }
    const_iterator get_msgs();
    bool reset() { return false; }

    operator bool() const { return fd > 0; }

    friend std::ostream &operator<<(std::ostream &os, const RX &rx);
};

class TX {
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    pid_t pid = -1;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
    int fd = -1;

    static constexpr char FIFO_PATH[] = "/tmp/HQ";

  public:
    TX() = default;

    TX(const TX &other) = delete;

    TX(TX &&old) { *this = std::move(old); }

    TX &operator=(TX &&old) {
        if (this != &old) {
            if (!*this)
                RAW_SYSCALL(1, SYS_close, fd);

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
            pid = old.pid;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
            fd = old.fd;
            old.fd = -1;
        }

        return *this;
    }

    ~TX() {
        if (!*this)
            RAW_SYSCALL(1, SYS_close, fd);
    }

    bool open() {
        fd = RAW_SYSCALL(3, SYS_open, reinterpret_cast<uintptr_t>(FIFO_PATH),
                         O_CLOEXEC | O_SYNC | O_WRONLY, 0);
        return *this;
    }

    inline bool send_msg2(const enum hq_msg_op op, const uintptr_t pointer,
                          const uintptr_t value) {
        const struct hq_msg msg = {
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
            .pid = pid,
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
            .op = op,
            .values = {pointer, value},
        };

#ifndef NDEBUG
        if (__builtin_expect(!*this, 0))
            return false;
#endif /* !NDEBUG */

        return RAW_SYSCALL(3, SYS_write, fd, reinterpret_cast<uintptr_t>(&msg),
                           sizeof(msg)) == static_cast<ssize_t>(sizeof(msg));
    }

    inline bool send_msg1(const enum hq_msg_op op, const uintptr_t value) {
        return send_msg2(op, 0, value);
    }

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    bool set_pid(pid_t p) {
        pid = p;
        return true;
    }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    operator bool() const { return fd > 0; }
};

} // namespace HQ::POSIX_FIFO

#endif /* _HQ_INTERFACES_POSIX_FIFO_H_ */
