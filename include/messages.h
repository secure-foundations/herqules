#ifndef _HQ_MESSAGES_H_
#define _HQ_MESSAGES_H_

#include "config.h"

// Must keep in sync with 'hq_fifo_csr.vh'
enum hq_msg_op {
    HQ_MSG_EMPTY,
    HQ_MSG_SYSCALL,
    HQ_MSG_INVALIDATE,
    HQ_MSG_COPY_BLOCK,
    HQ_MSG_INVALIDATE_BLOCK,
    HQ_MSG_MOVE_BLOCK,
    CFI_MSG_DEFINE,
    CFI_MSG_CHECK,
    CFI_MSG_CHECK_INVALIDATE,
    CFI_MSG_INIT_GLOBALS,
};

struct hq_msg {
    pid_t pid __attribute__((__aligned__(8)));
    enum hq_msg_op op __attribute__((__aligned__(8)));
    uintptr_t values[2];
} __attribute__((__aligned__(8)));

// With four-level paging, 48th bit is used to denote kernel space, and
// remaining 47 bits denote user-space virtual addresses. Since all address
// must be in virtual space, we can store the size in the upper 17 bits.
#define EMBED_ADDRESS_SIZE_HIGH(ptr, sz)                                       \
    (((uint64_t)ptr & ((1ULL << 47) - 1ULL)) |                                 \
     ((uint64_t)(sz & ~((1ULL << 17) - 1ULL)) << 30))
#define EMBED_ADDRESS_SIZE_LOW(ptr, sz)                                        \
    (((uint64_t)ptr & ((1ULL << 47) - 1ULL)) | ((uint64_t)sz << 47))
#define ADDRESS_FROM_EMBED(e) (e & ((1ULL << 47) - 1ULL))
#define SIZE_FROM_EMBED(eh, el)                                                \
    (((eh & ~((1ULL << 47) - 1ULL)) >> 30) |                                   \
     ((el & ~((1ULL << 47) - 1ULL)) >> 47))

// Option for prctl() to enable HQ
#define PR_HQ 100

#endif /* _HQ_MESSAGES_H_ */
