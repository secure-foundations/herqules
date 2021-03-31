#ifndef _HQ_VERIFIER_MESSAGES_H_
#define _HQ_VERIFIER_MESSAGES_H_

#include "config.h"

#ifdef __KERNEL__
#include <asm/unistd.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#define NUM_SYSCALLS NR_syscalls
#else
#include <asm-generic/unistd.h>
#include <linux/ioctl.h>
#define NUM_SYSCALLS __NR_syscalls
#endif

enum hq_verifier_msg_op {
    // Shared page used to notify the verifier of new messages from kernel
    HQ_VERIFIER_MSG_NOTIFY,
    // Create policy context from a cloned/forked process
    HQ_VERIFIER_MSG_CLONE,
    // Create policy context and monitor an existing process
    HQ_VERIFIER_MSG_MONITOR,
    // Delete policy context for a terminated process
    HQ_VERIFIER_MSG_TERMINATE,
};

struct hq_verifier_msg {
    pid_t pid;
    enum hq_verifier_msg_op op;
    uintptr_t value;
    char comm[16];
} __attribute__((__aligned__(8)));

struct hq_verifier_notify {
    uint64_t rd_counter, wr_counter;
};

// Must round to page size in order to remap to userspace
#define NOTIFY_MAP_SIZE                                                        \
    ((sizeof(struct hq_verifier_notify) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

#define IOCTL_KILL_TGID _IO('h', 0)

#ifdef HQ_CHECK_SYSCALL
struct hq_syscall {
    int32_t ok;
};

// Must round to page size in order to remap to userspace
#define SYSCALL_MAP_SIZE                                                       \
    ((sizeof(struct hq_syscall) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#endif /* HQ_CHECK_SYSCALL */

#endif /* _HQ_VERIFIER_MESSAGES_H_ */
