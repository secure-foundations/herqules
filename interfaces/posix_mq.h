#ifndef _HQ_INTERFACES_POSIX_MQ_H_
#define _HQ_INTERFACES_POSIX_MQ_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <ostream>

#include <fcntl.h>
#include <limits.h>
#include <mqueue.h>
#include <sys/stat.h>

#include "messages.h"
#include "syscalls.h"

namespace HQ::POSIX_MQ {

// See HARD_MSGMAX in linux/include/ipc_namespace.h
static constexpr size_t BUFFER_SIZE =
    std::min(HQ_INTERFACE_APPLICATION_SIZE / sizeof(struct hq_msg), 65536UL);
static constexpr char QUEUE_NAME[] = "/HQ";

// Receives will block until data is available, and sends will block if
// underlying queue is full
class RX {

    mqd_t queue = -1;
    std::array<struct hq_msg, BUFFER_SIZE> msgs;

  public:
    using const_iterator = decltype(msgs)::const_iterator;

    RX() = default;

    RX(const RX &other) = delete;

    RX(RX &&old) { *this = std::move(old); }

    RX &operator=(RX &&old) {
        if (this != &old) {
            if (*this)
                mq_close(queue);

            queue = old.queue;
            msgs = std::move(old.msgs);

            old.queue = -1;
        }

        return *this;
    }

    ~RX() {
        if (*this) {
            mq_unlink(QUEUE_NAME);
            mq_close(queue);
        }
    }

    bool open();
    const_iterator begin() { return msgs.begin(); }
    const_iterator get_msgs();
    bool reset() { return false; }

    operator bool() const { return queue > 0; }

    friend std::ostream &operator<<(std::ostream &os, const RX &rx);
};

class TX {
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    pid_t pid = -1;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
    mqd_t queue = -1;

  public:
    TX() = default;

    TX(const TX &other) = delete;

    TX(TX &&old) { *this = std::move(old); }

    TX &operator=(TX &&old) {
        if (this != &old) {
            if (queue >= 0)
                RAW_SYSCALL(1, SYS_close, queue);

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
            pid = old.pid;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
            queue = old.queue;

            old.queue = -1;
        }

        return *this;
    }

    ~TX() {
        if (queue >= 0)
            RAW_SYSCALL(1, SYS_close, queue);
    }

    bool open() {
        queue = RAW_SYSCALL(4, SYS_mq_open,
                            reinterpret_cast<uintptr_t>(&QUEUE_NAME[1]),
                            O_CLOEXEC | O_SYNC | O_WRONLY, 0,
                            reinterpret_cast<uintptr_t>(nullptr));
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

        return !RAW_SYSCALL(
            5, SYS_mq_timedsend, queue, reinterpret_cast<uintptr_t>(&msg),
            sizeof(msg), MQ_PRIO_MAX - 1, reinterpret_cast<uintptr_t>(nullptr));
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

    operator bool() const { return queue > 0; }
};

} // namespace HQ::POSIX_MQ

#endif /* _HQ_INTERFACES_POSIX_MQ_H_ */
