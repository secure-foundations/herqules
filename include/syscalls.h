#ifndef _HQ_SYSCALLS_H_
#define _HQ_SYSCALLS_H_

#include <sys/syscall.h>

#include "compat.h"
#include "runtime.h"

#define IS_ERR_PTR(x) ((uintptr_t)x >= (unsigned long)-MAX_ERRNO)

#define SYSCALL_RAW_FUNCTION __hq_raw_syscall
#define RAW_SYSCALL(n, ...) __hq_raw_syscall##n(__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
static __attribute__((always_inline)) inline long __hq_raw_syscall0(long num) {
    long ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(num)
                 : "memory", "cc", "r11", "cx");
    return ret;
}

static __attribute__((always_inline)) inline long
__hq_raw_syscall1(long num, const uintptr_t a1) {
    long ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(num), "D"(a1)
                 : "memory", "cc", "r11", "cx");
    return ret;
}

static __attribute__((always_inline)) inline long
__hq_raw_syscall2(long num, const uintptr_t a1, const uintptr_t a2) {
    long ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(num), "D"(a1), "S"(a2)
                 : "memory", "cc", "r11", "cx");
    return ret;
}

static __attribute__((always_inline)) inline long
__hq_raw_syscall3(long num, const uintptr_t a1, const uintptr_t a2,
                  const uintptr_t a3) {
    long ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(num), "D"(a1), "S"(a2), "d"(a3)
                 : "memory", "cc", "r11", "cx");
    return ret;
}

static __attribute__((always_inline)) inline long
__hq_raw_syscall4(long num, const uintptr_t a1, const uintptr_t a2,
                  const uintptr_t a3, const uintptr_t _a4) {
    long ret;
    long register a4 asm("r10") = _a4;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(num), "D"(a1), "S"(a2), "d"(a3), "r"(a4)
                 : "memory", "cc", "r11", "cx");
    return ret;
}

static __attribute__((always_inline)) inline long
__hq_raw_syscall5(long num, const uintptr_t a1, const uintptr_t a2,
                  const uintptr_t a3, const uintptr_t _a4,
                  const uintptr_t _a5) {
    long ret;
    long register a4 asm("r10") = _a4;
    long register a5 asm("r8") = _a5;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(num), "D"(a1), "S"(a2), "d"(a3), "r"(a4), "r"(a5)
                 : "memory", "cc", "r11", "cx");
    return ret;
}

static __attribute__((always_inline)) inline long
__hq_raw_syscall6(long num, const uintptr_t a1, const uintptr_t a2,
                  const uintptr_t a3, const uintptr_t _a4, const uintptr_t _a5,
                  const uintptr_t _a6) {
    long ret;
    long register a4 asm("r10") = _a4;
    long register a5 asm("r8") = _a5;
    long register a6 asm("r9") = _a6;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(num), "D"(a1), "S"(a2), "d"(a3), "r"(a4), "r"(a5),
                   "r"(a6)
                 : "memory", "cc", "r11", "cx");
    return ret;
}
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _HQ_SYSCALLS_H_ */
