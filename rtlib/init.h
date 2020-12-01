#ifndef _HQ_RTLIB_INIT_H_
#define _HQ_RTLIB_INIT_H_

#include <cstdint>

#include <asm/prctl.h>
#include <sys/types.h>

#include "config.h"
#include "intrinsics.h"
#include "syscalls.h"

class gs_data {
  public:
    pid_t pid;

    uintptr_t get_gs() {
#ifdef __FSGSBASE__
        return _readgsbase_u64();
#else
        void *addr;
        if (RAW_SYSCALL(2, SYS_arch_prctl, ARCH_GET_GS,
                        reinterpret_cast<uintptr_t>(&addr)))
            return -1;
        return reinterpret_cast<uintptr_t>(addr);
#endif /* __FSGSBASE__ */
    }

    bool set_gs() {
        uintptr_t addr = reinterpret_cast<uintptr_t>(&pid);
#ifdef __FSGSBASE__
        _writefsbase_u64(addr);
        return true;
#else
        return !RAW_SYSCALL(2, SYS_arch_prctl, ARCH_SET_GS, addr);
#endif /* __FSGSBASE__ */
    }
};

#endif /* _HQ_RTLIB_INIT_H_ */
