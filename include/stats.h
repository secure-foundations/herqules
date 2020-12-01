#ifndef _HQ_STATS_H_
#define _HQ_STATS_H_

#include "config.h"

/* List of all statistics
 * MAX_ENTRIES: Maximum number of pointer entries
 * NUM_FAILS: Number of messages that failed to execute
 * NUM_DEFINES: Number of define messages
 * NUM_CHECKS: Number of check messages
 * NUM_INVALIDATE: Number of invalidate messages
 * NUM_COPIES: Number of copy block messages
 * NUM_MOVES: Number of move block messages
 * NUM_FREES: Number of invalidate block messages
 * NUM_SYSCALLS: Number of system call messages
 * NUM_FORKS: Number of process forks
 * NUM_SYSCALLS_BELOW: Number of system calls below the sleep threshold
 * NUM_SYSCALLS_ABOVE: Number of system calls that exceed the sleep threshold
 */
#define HQ_STATS_LIST                                                          \
    HQ_STAT(MAX_ENTRIES)                                                       \
    HQ_STAT(NUM_FAILS)                                                         \
    HQ_STAT(NUM_DEFINES)                                                       \
    HQ_STAT(NUM_CHECKS)                                                        \
    HQ_STAT(NUM_CHECK_INVALIDATES)                                             \
    HQ_STAT(NUM_INVALIDATES)                                                   \
    HQ_STAT(NUM_COPIES)                                                        \
    HQ_STAT(NUM_MOVES)                                                         \
    HQ_STAT(NUM_FREES)                                                         \
    HQ_STAT(NUM_INIT_GLOBALS)                                                  \
    HQ_STAT(NUM_SYSCALLS)                                                      \
    HQ_STAT(NUM_FORKS)                                                         \
    HQ_STAT(NUM_SYSCALLS_BELOW)                                                \
    HQ_STAT(NUM_SYSCALLS_ABOVE)

// Auto-generated enum of all stats
#define HQ_STAT(x) HQ_STAT_##x,
enum hq_stats {
    HQ_STATS_LIST

        HQ_NUM_STATS,
};
#undef HQ_STAT

#endif /* _HQ_STATS_H_ */
