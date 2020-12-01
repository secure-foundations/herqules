#ifndef _HQ_CONFIG_H_
#define _HQ_CONFIG_H_

/* Cacheline size (bytes) */
#define CACHELINE_BYTES 64

/* Default buffer size (bytes) for application messages */
#define HQ_INTERFACE_APPLICATION_SIZE (1024 * 1024 * 1024)

/* Default buffer size (bytes) for kernel messages */
#define HQ_INTERFACE_KERNEL_SIZE 1024

/* Whether to enable write-combining for OPAE interface. Will need to build
 * applications and libraries with `-mclflushopt` */
// #define HQ_INTERFACE_OPAE_WC

/* When using DPDK, whether the RX and TX interfaces are being used by the same
 * process (e.g. tests/rtt). If so, DPDK should only be initialized once,
 * instead of separately by each interface. This should be set by the build
 * system only, but is here for completeness. */
// #define HQ_INTERFACE_DPDK_SAME_PROCESS

/* When using OPAE, whether to avoid direct MMIO access for compatibility with
 * the simulator for RX. Note that the simulator is not supported for TX. This
 * should be set by the build system only, but is here for completeness. */
// #define HQ_INTERFACE_OPAE_SIMULATE

/* Whether to enable unsafe application-defined PID in messages. This option
 * disables kernel update of the application PID to the underlying interface,
 * where supported (e.g. FPGA). Otherwise, assumes the last kernel-provided PID
 * for subsequent messages, which may be slightly racy for fast repeated
 * short-lived processes. */
// #define HQ_INTERFACE_UNSAFE_PID

/* Whether to enable concurrent-safe unsafe application-defined PID and
 * messaging. This is needed if applications may execute concurrently. */
// #define HQ_INTERFACE_UNSAFE_PID_CONCURRENT

/* Whether to enable futex-based waiting instead of busy-waiting for new
 * messages on the underlying interface, and if so, the number of seconds to
 * wait for wake, if supported. */
// #define HQ_INTERFACE_FUTEX 1

/* Whether the verifier should preserve statistics after instrumented processes
 * have exited */
#define HQ_PRESERVE_STATS

/* Whether to perform system call checking */
#define HQ_CHECK_SYSCALL

/* Whether to allow certain system calls for compatibility with rr */
// #define HQ_UNSAFE_COMPAT_RR

/* Whether to kill the application when a check fails */
#define HQ_ENFORCE_CHECKS

/* Whether to kill the application when the system call wait has exceeded a hard
 * threshold, and if so, the threshold in milliseconds */
#define HQ_ENFORCE_SYSCALL_HARD 2000

/* Threshold at which internal globals are initialized in verifier */
#define HQ_GLOBALS_INTERNAL_THRESHOLD 500

/* Threshold (ms) before sleeping while waiting on a system call */
#define HQ_SYSCALL_THRESHOLD 1

/* Sleep duration exponential backoff multiplier after exceeding threshold */
#define HQ_SYSCALL_SLEEP_MULTIPLIER 3

/* Maximum sleep interval (ms) while waiting on a system call */
#define HQ_SYSCALL_SLEEP_MAX 1000

/* For configuration affecting the LLVM instrumentation, refer to the
 * command-line options embedded within the LLVM plugin. */

#endif /* _HQ_CONFIG_H_ */
