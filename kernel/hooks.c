#include <linux/delay.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/ptrace.h>
#include <linux/rhashtable.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tracepoint.h>
#include <linux/uprobes.h>
#include <linux/version.h>

#include <asm/byteorder.h>
#include <asm/io.h>
#include <asm/prctl.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>

#include "compat.h"
#include "config.h"
#include "fpga.h"
#include "hooks.h"
#include "hq-interface.h"
#include "hq.h"
#include "interface.h"
#include "verifier.h"

/* Tracepoints */
// FIXME: For HQ_INTERFACE_UNSAFE_PID_CONCURRENT, need to update PID when about
// to be scheduled (e.g. signals)
static struct tracepoint *tp_sched_exit = NULL
#ifdef HQ_CHECK_SYSCALL
    ,
                         *tp_sys_enter = NULL
#endif /* HQ_CHECK_SYSCALL */
    ;

#if !defined(HQ_INTERFACE_UNSAFE_PID) && INTERFACE_TYPE == INTERFACE_TYPE_OPAE
// Either use the upstream kernel driver (dfl-afu, etc) or the old Intel driver
// from the opae-intel-fpga-driver package (intel-fpga-afu, etc)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include "dfl.h"
typedef struct dfl_feature_platform_data fpga_t;
#define FPGA_ID_AFU PORT_FEATURE_ID_AFU
#define FPGA_PORT_DRIVER DFL_FPGA_FEATURE_DEV_PORT
#define fpga_is_disabled(pdata) pdata->disable_count
#define fpga_get_feature_ioaddr(dev, id) dfl_get_feature_ioaddr_by_id(dev, id)
#else
#include "feature-dev.h"
typedef struct feature_platform_data fpga_t;
#define FPGA_ID_AFU FEATURE_ID_AFU
#define FPGA_PORT_DRIVER FPGA_FEATURE_DEV_PORT
#define fpga_is_disabled(pdata) 0
#define fpga_get_feature_ioaddr(dev, id) get_feature_ioaddr_by_id(dev, id)
#endif /* LINUX_VERSION_CODE */

fpga_t *fpga = NULL;
struct file *fpga_file = NULL;
void __iomem *fpga_mmio = NULL;
#endif /* !HQ_INTERFACE_UNSAFE_PID && INTERFACE_TYPE == INTERFACE_TYPE_OPAE    \
        */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
static inline unsigned long regs_get_kernel_argument(struct pt_regs *regs,
                                                     unsigned int n) {
    static const unsigned int argument_offs[] = {
#ifdef __i386__
        offsetof(struct pt_regs, ax),
        offsetof(struct pt_regs, cx),
        offsetof(struct pt_regs, dx),
#define NR_REG_ARGUMENTS 3
#else
        offsetof(struct pt_regs, di), offsetof(struct pt_regs, si),
        offsetof(struct pt_regs, dx), offsetof(struct pt_regs, cx),
        offsetof(struct pt_regs, r8), offsetof(struct pt_regs, r9),
#define NR_REG_ARGUMENTS 6
#endif
    };

    if (n >= NR_REG_ARGUMENTS) {
        n -= NR_REG_ARGUMENTS - 1;
        return regs_get_kernel_stack_nth(regs, n);
    } else
        return regs_get_register(regs, argument_offs[n]);
}
#endif /* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
static inline void regs_set_return_value(struct pt_regs *regs,
                                         unsigned long rc) {
    regs->ax = rc;
}
#endif /* LINUX_VERSION_CODE */

static void tracepoint_sched_exit(void *data, struct task_struct *task) {
    struct hq_ctx *app;
    pid_t tgid;

    // Check if this is the last thread from the thread group
    if (atomic_read(&task->signal->live))
        return;
    tgid = task_tgid_nr(task);

    rcu_read_lock();

    app = rhashtable_lookup(&hq_table, &tgid, hq_params);
    if (app
#ifdef HQ_PRESERVE_STATS
        && !app->dead
#endif /* HQ_PRESERVE_STATS */
    ) {
#ifdef HQ_PRESERVE_STATS
        app->dead = 1;
#endif /* HQ_PRESERVE_STATS */

        // Notify process has exited
        if (verifier_interface_on_exit(tgid))
            pr_warn("Cannot notify exit for tgid %d!\n", tgid);
    }

    rcu_read_unlock();
}

#ifdef HQ_CHECK_SYSCALL
static void tracepoint_sys_enter(void *data, struct pt_regs *regs, long id) {
    struct hq_ctx *app;
    pid_t tgid = task_tgid_nr(current);

    rcu_read_lock();

    app = rhashtable_lookup(&hq_table, &tgid, hq_params);
    if (app
#ifdef HQ_PRESERVE_STATS
        && !app->dead
#endif /* HQ_PRESERVE_STATS */
    ) {
        bool after = 0;
        unsigned long jiffies_start, sleep = 1;

#ifdef HQ_UNSAFE_COMPAT_RR
        // When running under rr, it may inject psuedo-syscalls with number
        // greater than or equal to RR_CALL_BASE (1000). Additionally, it may
        // modify the vDSO to perform system calls, so whitelist these too.
        if (id >= 1000 || id == __NR_clock_getres || id == __NR_clock_gettime ||
            id == __NR_getcpu || id == __NR_gettimeofday || id == __NR_time) {
            pr_info_ratelimited(
                "Allowing rr system call %ld in context tgid %d (%s)!\n", id,
                tgid, app->name);
            goto out;
        }
#endif /* HQ_UNSAFE_COMPAT_RR */

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
        // Skip check if retrieving PID, because the child needs a mechanism to
        // update its own PID after clone/fork
        if (id == __NR_getpid)
            goto out;
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

#if INTERFACE_TYPE == INTERFACE_TYPE_POSIX_FIFO ||                             \
    INTERFACE_TYPE == INTERFACE_TYPE_POSIX_MQ
        // Skip check on write if interacting with the interface
        if (
#if INTERFACE_TYPE == INTERFACE_TYPE_POSIX_FIFO
            id == __NR_write
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_MQ
            id == __NR_mq_timedsend
#endif /* INTERFACE_TYPE */
        ) {
            bool skip = false;
            struct fd f = fdget(regs_get_kernel_argument(regs, 0));
            if (f.file &&
#if INTERFACE_TYPE == INTERFACE_TYPE_POSIX_FIFO
                S_ISFIFO(file_inode(f.file)->i_mode)
#elif INTERFACE_TYPE == INTERFACE_TYPE_POSIX_MQ
                file_inode(f.file)->i_sb->s_magic == MQUEUE_MAGIC
#endif /* INTERFACE_TYPE */
            )
                skip = true;

            fdput(f);
            if (skip)
                goto out;
        }
#endif /* INTERFACE_TYPE */

        jiffies_start = jiffies;
        // Block system call until verifier has caught up
        while (1) {
            barrier();

            if (!pid_alive(current) || fatal_signal_pending(current))
                goto dead;

            if (!app->syscall) {
                pr_err("Missing system call buffer in tgid %d!\n", tgid);
                goto die;
            }

            // System call allowed, continue execution
            if (atomic_read_acquire((atomic_t *)app->syscall)) {
                atomic_set_release((atomic_t *)app->syscall, 0);
                atomic_inc(&app->stats[after ? HQ_STAT_NUM_SYSCALLS_ABOVE
                                             : HQ_STAT_NUM_SYSCALLS_BELOW]);
                goto out;
            }

#ifdef HQ_ENFORCE_SYSCALL_HARD
            // Kill if hard threshold exceeded
            if (time_is_before_jiffies(
                    jiffies_start +
                    msecs_to_jiffies(HQ_ENFORCE_SYSCALL_HARD))) {
                pr_err("Reached hard threshold of %d ms in tgid %d!\n",
                       HQ_ENFORCE_SYSCALL_HARD, tgid);
                goto die;
            }
#endif /* HQ_ENFORCE_SYSCALL_HARD */

            // Sleep if threshold exceeded to avoid blocking kernel thread
            if (time_is_before_jiffies(
                    jiffies_start + msecs_to_jiffies(HQ_SYSCALL_THRESHOLD))) {
                after = 1;

                pr_info_ratelimited("Waiting on syscall %ld for %d ms in "
                                    "context tgid %d (%s)!\n",
                                    id,
                                    jiffies_to_msecs(jiffies - jiffies_start),
                                    tgid, app->name);

                if (sleep < HQ_SYSCALL_SLEEP_MAX) {
                    usleep_range(sleep * 500, sleep * 1000);
                    sleep *= HQ_SYSCALL_SLEEP_MULTIPLIER;
                } else
                    msleep_interruptible(HQ_SYSCALL_SLEEP_MAX);
            }
        }

    die:
#ifdef HQ_ENFORCE_CHECKS
        pr_warn("Killing tgid %d (%s)!\n", tgid, app->name);
        send_sig(SIGKILL, current, 1);
#endif /* HQ_ENFORCE_CHECKS */
    dead:
        atomic_inc(&app->stats[HQ_STAT_NUM_FAILS]);
    }

out:
    rcu_read_unlock();
}
#endif /* HQ_CHECK_SYSCALL */

// Tracepoints are not exported, must search through list
static void lookup_tracepoints(struct tracepoint *tp, void *ignore) {
    if (!tp_sched_exit && !strcmp("sched_process_exit", tp->name))
        tp_sched_exit = tp;
#ifdef HQ_CHECK_SYSCALL
    else if (!tp_sys_enter && !strcmp("sys_enter", tp->name))
        tp_sys_enter = tp;
#endif /* HQ_CHECK_SYSCALL */
}

#if !defined(HQ_INTERFACE_UNSAFE_PID) && INTERFACE_TYPE == INTERFACE_TYPE_OPAE
static int match_fpga_port(struct device *dev, const void *data) {
    int ret = 0;
    fpga_t *pdata = dev_get_platdata(dev);

    if (pdata) {
        mutex_lock(&pdata->lock);
        if (!fpga_is_disabled(pdata)) {
            const u8 guid[] = {AFU_UUID};
            void __iomem *base = fpga_get_feature_ioaddr(dev, FPGA_ID_AFU);
            const u64 afuh = ioread64(base + REG_AFU_ID_H),
                      aful = ioread64(base + REG_AFU_ID_L);

            // Check the AFU has a matching GUID
            if (((u64 *)guid)[1] == be64_to_cpu(aful) &&
                ((u64 *)guid)[0] == be64_to_cpu(afuh))
                ret = 1;
            else
                pr_warn("Found FPGA AFU with different GUID %llx%llx!\n", afuh,
                        aful);
        }
        mutex_unlock(&pdata->lock);
    }

    return ret;
}
#endif /* !HQ_INTERFACE_UNSAFE_PID && INTERFACE_TYPE == INTERFACE_TYPE_OPAE    \
        */

int tracepoints_insert(void) {
    int ret;

    if (!tp_sched_exit
#ifdef HQ_CHECK_SYSCALL
        || !tp_sys_enter
#endif /* HQ_CHECK_SYSCALL */
    )
        for_each_kernel_tracepoint(lookup_tracepoints, NULL);

    if (!tp_sched_exit) {
        pr_err("Could not find tracepoint 'sched_process_exit'!\n");
        return -ENODEV;
    }

#ifdef HQ_CHECK_SYSCALL
    if (!tp_sys_enter) {
        pr_err("Could not find tracepoint 'sys_enter'!\n");
        return -ENODEV;
    }
#endif /* HQ_CHECK_SYSCALL */

    if ((ret = tracepoint_probe_register(tp_sched_exit, tracepoint_sched_exit,
                                         NULL))) {
        pr_err("Could not register tracepoint 'sched_process_exit'!\n");
        tp_sched_exit = NULL;
        return ret;
    }

#ifdef HQ_CHECK_SYSCALL
    if ((ret = tracepoint_probe_register(tp_sys_enter, tracepoint_sys_enter,
                                         NULL))) {
        pr_err("Could not register tracepoint 'sys_enter'!\n");
        tp_sys_enter = NULL;
        return ret;
    }
#endif /* HQ_CHECK_SYSCALL */

    return 0;
}

void tracepoints_remove(void) {
#ifdef HQ_CHECK_SYSCALL
    if (tp_sys_enter &&
        tracepoint_probe_unregister(tp_sys_enter, tracepoint_sys_enter, NULL)) {
        pr_err("Could not unregister tracepoint 'sys_enter'!\n");
        return;
    }
#endif /* HQ_CHECK_SYSCALL */

    if (tp_sched_exit && tracepoint_probe_unregister(
                             tp_sched_exit, tracepoint_sched_exit, NULL)) {
        pr_err("Could not unregister tracepoint 'sched_process_exit'!\n");
        return;
    }

    tracepoint_synchronize_unregister();
}

/* kprobes */

// Hook to copy HQ state when a process is cloned
static int clone_copy_context(struct kprobe *kp, struct pt_regs *regs) {
    struct task_struct *clone =
        (struct task_struct *)regs_get_kernel_argument(regs, 0);
    pid_t tgid = task_tgid_nr(current), ctgid = task_tgid_nr(clone);
    unsigned long clone_flags = regs_get_kernel_argument(regs, 1);
    struct hq_ctx *app, *app_clone;
    int ret = 0;

    // Only a thread is being cloned, don't need to copy entry
    if (clone_flags & CLONE_THREAD)
        return ret;

    rcu_read_lock();

    // Check if the process is under HQ and copy entry if it is
    app = rhashtable_lookup(&hq_table, &tgid, hq_params);
    if (!app
#ifdef HQ_PRESERVE_STATS
        || app->dead
#endif /* HQ_PRESERVE_STATS */
    )
        goto out;

    atomic_inc(&app->stats[HQ_STAT_NUM_FORKS]);

    if (clone_flags & CLONE_VM)
        pr_warn("Unsupported cloned memory space in context tgid %d for "
                "process '%s'...\n",
                tgid, app->name);

    if (!(app_clone = kmalloc(sizeof(*app_clone), GFP_KERNEL))) {
        pr_err("Cannot allocate context for tgid %d!\n", tgid);
        ret = -ENOMEM;
        goto out;
    }

    if ((ret = copy_hq_context(app_clone, app, ctgid))) {
        pr_err("Cannot copy context for tgid %d!\n", tgid);
        kfree(app_clone);
        goto out;
    }

    if ((ret =
             rhashtable_insert_fast(&hq_table, &app_clone->node, hq_params))) {
        pr_err("Cannot insert context for tgid %d!\n", tgid);
        free_hq_context(app_clone, (void *)1);
        goto out;
    }

    ret = verifier_interface_on_clone(tgid, app_clone);
    if (ret)
        pr_err("Cannot notify clone for tgid %d!\n", tgid);

out:
    rcu_read_unlock();
    return ret;
}

static struct kprobe clone_process = {
    .symbol_name = "uprobe_copy_process",
    .pre_handler = clone_copy_context,
};

// Hook to enable HQ for a process
static int notify_hq(struct kretprobe_instance *ri, struct pt_regs *regs) {
    int option = regs_get_kernel_argument(regs, 0);
    unsigned long arg2 = regs_get_kernel_argument(regs, 1);
    pid_t tgid = task_tgid_nr(current);

    if (option == PR_HQ && arg2 == 1) {
        struct hq_ctx *app;
        int ret = 0;

        if (!verifier_is_connected()) {
            pr_err("Cannot enable HQ for tgid %d (%s), missing verifier!\n",
                   tgid, current->comm);
            return -ENODEV;
        }

        rcu_read_lock();
    lookup:
        // Ensure no context exists for this process
        app = rhashtable_lookup(&hq_table, &tgid, hq_params);
        if (app) {
            if (
#ifdef HQ_PRESERVE_STATS
                !app->dead
#else
                0
#endif /* HQ_PRESERVE_STATS */
            ) {
                pr_err("Context already exists for tgid %d (%s)!\n", tgid,
                       app->name);
                ret = -EEXIST;
                goto err;
            } else {
                pr_warn("Overwriting stale context for tgid %d (%s)!\n", tgid,
                        app->name);

                // Initialize the context
                get_task_comm(app->name, current);
                if ((ret = init_hq_context(app, tgid))) {
                    pr_err("Cannot initialize context for tgid %d!\n", tgid);
                    kfree(app);
                    goto err;
                }
            }
        } else {
            // Allocate the per-process context
            if (!(app = kmalloc(sizeof(*app), GFP_KERNEL))) {
                pr_err("Cannot allocate context for tgid %d!\n", tgid);
                ret = -ENOMEM;
                goto err;
            }

            // Initialize the context.
            get_task_comm(app->name, current);
            if ((ret = init_hq_context(app, tgid))) {
                pr_err("Cannot initialize context for tgid %d!\n", tgid);
                kfree(app);
                goto err;
            }

            // Insert the context into the hashtable
            if (rhashtable_insert_fast(&hq_table, &app->node, hq_params)) {
                pr_err("Cannot insert context for tgid %d!\n", tgid);
                free_hq_context(app, (void *)1);
                goto lookup;
            }
        }

#if !defined(HQ_INTERFACE_UNSAFE_PID) && INTERFACE_TYPE == INTERFACE_TYPE_OPAE
        if (fpga) {
            pr_info("Updating PID for context tgid %d\n", tgid);
            // Update PID register on FPGA
            iowrite64(tgid, fpga_mmio + REG_PID);
#ifdef HQ_INTERFACE_OPAE_WC
            clwb(fpga_mmio + REG_PID);
#endif /* HQ_INTERFACE_OPAE_WC */
        }
#endif /* !HQ_INTERFACE_UNSAFE_PID && INTERFACE_TYPE == INTERFACE_TYPE_OPAE    \
        */

        // Send the syscall buffer to userspace verifier
        if ((ret = verifier_interface_notify(tgid, app)))
            pr_err("Cannot notify context for tgid %d!\n", tgid);

    err:
        rcu_read_unlock();
        return ret;
    }

    // Always disable the post-handler
    return -1;
}

static int notify_hq_post(struct kretprobe_instance *ri, struct pt_regs *regs) {
    // Change the return value to success
    if ((int)regs_return_value(regs) == -ENOSYS)
        regs_set_return_value(regs, 0);
    return 0;
}

static struct kretprobe notify_prctl = {
    .kp.symbol_name = "security_task_prctl",
    .handler = notify_hq_post,
    .entry_handler = notify_hq,
    .maxactive = 2 * NR_CPUS,
};

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
static int change_gs(struct kprobe *kp, struct pt_regs *regs) {
    struct task_struct *task =
        (struct task_struct *)regs_get_kernel_argument(regs, 0);
    int option = regs_get_kernel_argument(regs, 1);
    unsigned long arg2 = regs_get_kernel_argument(regs, 2);
    pid_t tgid = task_tgid_nr(task);

    if (option == ARCH_SET_GS && arg2 < TASK_SIZE_MAX) {
        struct hq_ctx *app;

        rcu_read_lock();
        // Ensure no context exists for this process
        app = rhashtable_lookup(&hq_table, &tgid, hq_params);
        if (app
#ifdef HQ_PRESERVE_STATS
            && !app->dead
#endif /* HQ_PRESERVE_STATS */
        )
            pr_warn("Updating %%GS to 0x%lx for tgid %d (%s)!\n", arg2, tgid,
                    app->name);
    }

    return 0;
}

static struct kprobe notify_arch_prctl = {
    .symbol_name = "do_arch_prctl_64",
    .pre_handler = change_gs,
};
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

int kprobes_insert(void) {
    int ret = 0;

    if ((ret = register_kprobe(&clone_process))) {
        pr_err("Could not find kprobe symbol '%s'!\n",
               clone_process.symbol_name);
        return ret;
    }

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    if ((ret = register_kprobe(&notify_arch_prctl))) {
        pr_err("Could not find kprobe symbol '%s'!\n",
               notify_arch_prctl.symbol_name);
        return ret;
    }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    if ((ret = register_kretprobe(&notify_prctl))) {
        pr_err("Could not find kretprobe symbol '%s'!\n",
               notify_prctl.kp.symbol_name);
        return ret;
    }

    return ret;
}

void kprobes_remove(void) {
    if (notify_prctl.nmissed)
        pr_warn("Missed calls to prctl detected!\n");

    unregister_kprobe(&clone_process);
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    unregister_kprobe(&notify_arch_prctl);
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
    unregister_kretprobe(&notify_prctl);
}

int fpga_init(void) {
#if !defined(HQ_INTERFACE_UNSAFE_PID) && INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    struct device_driver *drv =
        driver_find(FPGA_PORT_DRIVER, &platform_bus_type);
    struct device *dev = driver_find_device(drv, NULL, NULL, match_fpga_port);

    if (!dev)
        return -ENODEV;

    fpga = dev_get_platdata(dev);
    // Open the file so that the driver can reset the port on close
    fpga_file = filp_open(FPGA_PATH, O_RDWR, 0);
    // Fetch the physical address of the fpga_mmio region
    fpga_mmio = fpga_get_feature_ioaddr(dev, FPGA_ID_AFU);
    return fpga && fpga_file && fpga_mmio ? 0 : -EINVAL;
#else
    return 0;
#endif /* !HQ_INTERFACE_UNSAFE_PID && INTERFACE_TYPE == INTERFACE_TYPE_OPAE    \
        */
}

void fpga_finish(void) {
#if !defined(HQ_INTERFACE_UNSAFE_PID) && INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    if (fpga) {
        fpga_mmio = NULL;
        fput(fpga_file);
        fpga_file = NULL;
        fpga = NULL;
    }
#endif /* !HQ_INTERFACE_UNSAFE_PID && INTERFACE_TYPE == INTERFACE_TYPE_OPAE    \
        */
}
