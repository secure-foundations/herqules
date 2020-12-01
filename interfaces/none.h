#ifndef _HQ_INTERFACES_NONE_H_
#define _HQ_INTERFACES_NONE_H_

#include <cstdint>
#include <ostream>
#include <utility>

#include "messages.h"

namespace HQ::NONE {

class RX {
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

    ~RX() {}

    bool open() { return true; }
    const_iterator begin() { return &msg; }
    const_iterator get_msgs() { return &msg + 1; }
    bool reset() { return false; }

    operator bool() const { return true; }

    ssize_t get_drops() const { return 0; }

    friend std::ostream &operator<<(std::ostream &os, const RX &rx) {
        return os << "NONE::RX";
    }
};

class TX {
    bool init = false;

  public:
    TX() = default;

    TX(const TX &other) = delete;

    TX(TX &&old) { *this = std::move(old); }

    TX &operator=(TX &&old) {
        if (this != &old) {
        }

        return *this;
    }

    ~TX() {}

    bool open() { return (init = true); }
    bool send_msg2(const enum hq_msg_op op, const uintptr_t pointer,
                   const uintptr_t value) {
        return true;
    }
    inline bool send_msg1(const enum hq_msg_op op, const uintptr_t value) {
        return send_msg2(op, 0, value);
    }

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    bool set_pid(pid_t pid) { return true; }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    operator bool() const { return init; }
};

} // namespace HQ::NONE

#endif /* _HQ_INTERFACES_NONE_H_ */
