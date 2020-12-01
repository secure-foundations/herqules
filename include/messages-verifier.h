#ifndef _HQ_VERIFIER_MESSAGES_H_
#define _HQ_VERIFIER_MESSAGES_H_

#include <linux/types.h>

#include "config.h"

enum hq_verifier_msg_op {
    HQ_VERIFIER_MSG_NOTIFY,
    HQ_VERIFIER_MSG_CLONE,
    HQ_VERIFIER_MSG_SYSCALL_PAGE,
    HQ_VERIFIER_MSG_TERMINATE,
};

struct hq_verifier_msg {
    pid_t pid;
    enum hq_verifier_msg_op op;
    uintptr_t value;
} __attribute__((__aligned__(8)));

struct hq_verifier_notify {
    int pending;
};

// Must round to page size in order to remap to userspace
#define SYSCALL_MAP_SIZE                                                       \
    (((sizeof(struct hq_verifier_msg) + (PAGE_SIZE - 1)) / PAGE_SIZE) *        \
     PAGE_SIZE)

#endif /* _HQ_VERIFIER_MESSAGES_H_ */
