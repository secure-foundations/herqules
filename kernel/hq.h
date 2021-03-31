#ifndef _HQ_H_
#define _HQ_H_

#include <linux/atomic.h>
#include <linux/rhashtable.h>

#include "config.h"
#include "interfaces.h"
#include "messages-verifier.h"
#include "messages.h"
#include "stats.h"

#define HQ_CLASS_NAME "hq"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/* Hashtable entry for tracking per-process state */
struct hq_ctx {
    pid_t tgid;
    struct rhash_head node;
    struct rcu_head rcu;

#ifdef HQ_PRESERVE_STATS
    // Whether the process is dead, to prevent against tgid wraparound
    int dead;
#endif /* HQ_PRESERVE_STATS */

    // Process name
    char name[TASK_COMM_LEN];

#ifdef HQ_CHECK_SYSCALL
    // Pointer to system call identifier
    struct hq_syscall *syscall;
#endif /* HQ_CHECK_SYSCALL */

    // Statistics
    atomic_t stats[HQ_NUM_STATS];
};

#endif /* _HQ_H_ */
