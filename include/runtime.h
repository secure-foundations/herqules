#ifndef _HQ_RUNTIME_H_
#define _HQ_RUNTIME_H_

#include "config.h"

#define __STR(x) (#x)
#define STR(x) __STR(x)

// Initialize underlying interface. Automatically called by C runtime library
// during initialization.
#define INIT_FUNCTION __hq_init
// Called to define all global pointers at program startup
#define CFI_INIT_GLOBALS_FUNCTION __hq_cfi_init_globals

#define INIT_ARRAY_INTERNAL __hq_init_array_internal
#define INIT_ARRAY_EXTERNAL __hq_init_array_external
#define INIT_SECTION_INTERNAL .hq_init
#define INIT_FUNCTION_EXTERNAL __hq_init_module

#define POINTER_CHECK_FUNCTION __hq_pointer_check
#define POINTER_CHECK_INVALIDATE_FUNCTION __hq_pointer_check_invalidate
#define CFI_POINTER_DEFINE_FUNCTION __hq_cfi_pointer_define

#define POINTER_INVALIDATE_FUNCTION __hq_pointer_invalidate
#define POINTER_MEMCPY_FUNCTION __hq_pointer_memcpy
#define POINTER_MEMMOVE_FUNCTION __hq_pointer_memmove

#define POINTER_FREE_FUNCTION __hq_pointer_free
#define POINTER_REALLOC_FUNCTION __hq_pointer_realloc

#define PID_UPDATE_FUNCTION __hq_update_pid
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
#define PID_SEND_FUNCTION __hq_send_pid

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
void __hq_send_pid(void);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

#define SYSCALL_FUNCTION __hq_syscall

typedef struct {
    const uintptr_t ptr;
    const uintptr_t val;
} hq_init_t;

#define POINTER_IS_MISALIGNED(x) ((x)&7)

#endif /* _HQ_RUNTIME_H_ */
