#ifndef _HQ_INTERFACES_MODEL_SIM_H_
#define _HQ_INTERFACES_MODEL_SIM_H_

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <ostream>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compat.h"
#include "config.h"
#include "interfaces.h"
#include "intrinsics.h"
#include "messages.h"
#include "syscalls.h"

#ifdef HQ_INTERFACE_UNSAFE_PID_CONCURRENT
#error "Unsafe concurrent PID not supported!"
#endif /* HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

namespace HQ::MODEL_SIM {

class RX {
    struct hq_msg msg[2];

  public:
    using const_iterator = const struct hq_msg *;

    bool open();
    const_iterator begin() { return &msg[0]; }
    const_iterator get_msgs() { return &msg[1]; }
    bool reset() { return true; }

    operator bool() const { return true; }

    friend std::ostream &operator<<(std::ostream &os, const RX &rx);
};

class TX {
  public:
    bool open() { return true; }

    inline bool send_msg2(const enum hq_msg_op op, const uintptr_t pointer,
                          const uintptr_t value) {
#ifndef NDEBUG
        if (__builtin_expect(!*this, 0))
            return false;
#endif /* !NDEBUG */

        auto msg = fill256(
#ifdef HQ_INTERFACE_UNSAFE_PID
            pid
#else
            0
#endif /* HQ_INTERFACE_UNSAFE_PID */
            ,
            op, pointer, value);
        // This instruction is hooked in the simulator to emulate the append
        asm volatile("xchg %%rcx, %%rcx" : : "x"(msg));
        return true;
    }

    inline bool send_msg1(const enum hq_msg_op op, const uintptr_t value) {
        return send_msg2(op, 0, value);
    }

#ifdef HQ_INTERFACE_UNSAFE_PID
    bool set_pid(pid_t p) { return true; }
#endif /* HQ_INTERFACE_UNSAFE_PID */

    operator bool() const { return true; }
};

} // namespace HQ::MODEL_SIM

#endif /* _HQ_INTERFACES_MODEL_SIM_H_ */
