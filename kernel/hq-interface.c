#include <linux/debugfs.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rhashtable.h>
#include <linux/sched/signal.h>

#include <asm/pgtable.h>

#include "config.h"
#include "hooks.h"
#include "hq.h"
#include "interface.h"
#include "messages-verifier.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Generic interface for HQ");
MODULE_VERSION("0.1");

/* Per-tgid hashtable */
const struct rhashtable_params hq_params = {
    .key_len = sizeof(((struct hq_ctx *)NULL)->tgid),
    .key_offset = offsetof(struct hq_ctx, tgid),
    .head_offset = offsetof(struct hq_ctx, node),
};
struct rhashtable hq_table;

/* Debugfs directory */
struct dentry *debugfs;

/* Exported interface for getting this module */
struct module *hq_get_module(void) {
    return THIS_MODULE;
}
EXPORT_SYMBOL(hq_get_module);

/* Implementation of per-application context functions */
int init_hq_context(struct hq_ctx *ctx, pid_t tgid) {
    int ret = 0;

    ctx->tgid = tgid;

#ifdef HQ_PRESERVE_STATS
    ctx->dead = 0;
#endif /* HQ_PRESERVE_STATS */

    pr_info("Creating context tgid %d for process '%s'...\n", tgid, ctx->name);

#ifdef HQ_CHECK_SYSCALL
    // Allocate aligned page(s)
    ctx->syscall = (struct hq_syscall *)__get_free_pages(
        GFP_KERNEL | __GFP_ZERO, get_order(SYSCALL_MAP_SIZE));
#endif /* HQ_CHECK_SYSCALL */

    memset(ctx->stats, 0, sizeof(*ctx->stats));
    return ret;
}

int copy_hq_context(struct hq_ctx *new, struct hq_ctx *old, pid_t tgid) {
    int max, ret;

    strncpy(new->name, old->name, sizeof(new->name));
    if ((ret = init_hq_context(new, tgid)))
        return ret;

    pr_info("Copying context from %d to %d for process '%s'...\n", old->tgid,
            tgid, old->name);

    max = atomic_read(&old->stats[HQ_STAT_MAX_ENTRIES]);
    atomic_set(&new->stats[HQ_STAT_MAX_ENTRIES], max);

    return ret;
}

void free_hq_context(void *pctx, void *erase) {
    struct hq_ctx *ctx = pctx;

#ifdef HQ_CHECK_SYSCALL
    // Free the pages
    free_pages((unsigned long)ctx->syscall, get_order(SYSCALL_MAP_SIZE));
    ctx->syscall = NULL;
#endif /* HQ_CHECK_SYSCALL */

    // To preserve statistics, delete context only if module is being unloaded
    if (erase) {
#ifdef HQ_ENFORCE_CHECKS
        struct task_struct *task;
#endif /* HQ_ENFORCE_CHECKS */

        pr_info("Destroying context tgid %d for process '%s'...\n", ctx->tgid,
                ctx->name);

#ifdef HQ_ENFORCE_CHECKS
        // Kill the process if it is still running
        if ((task = pid_task(find_vpid(ctx->tgid), PIDTYPE_PID)) &&
            pid_alive(task)) {
            pr_warn("Killing tgid %d, freeing context!\n", ctx->tgid);
            send_sig(SIGKILL, task, 1);
        }
#endif /* HQ_ENFORCE_CHECKS */

        kfree_rcu(ctx, rcu);
    }
}

/* Implementation of module init/exit functions */
static int __init hq_mod_init(void) {
    int ret;

    // Create per-tgid hashtable
    if ((ret = rhashtable_init(&hq_table, &hq_params))) {
        pr_warn("Unable to create hashtable!\n");
        return ret;
    }

    // Initialize FPGA
    if ((ret = fpga_init())) {
        pr_warn("Unable to find FPGA device!\n");
        goto err_hashtable;
    }

    // Insert tracepoints
    if ((ret = tracepoints_insert())) {
        pr_warn("Unable to insert tracepoints!\n");
        goto err_fpga;
    }

    // Insert kprobes
    if ((ret = kprobes_insert())) {
        pr_warn("Unable to insert kprobes!\n");
        goto err_tracepoints;
    }

    // Create debugfs directory
    debugfs = debugfs_create_dir(HQ_CLASS_NAME, NULL);
    if (IS_ERR(debugfs)) {
        pr_warn("Creation of debugfs directory " HQ_CLASS_NAME " failed!\n");
        ret = PTR_ERR(debugfs);
        goto err_kprobes;
    }

    // Register interface
    if ((ret = interface_register())) {
        pr_warn("Unable to register interface!\n");
        goto err_debugfs;
    }

    return ret;

err_debugfs:
    debugfs_remove_recursive(debugfs);
err_kprobes:
    kprobes_remove();
err_tracepoints:
    tracepoints_remove();
err_hashtable:
    fpga_finish();
err_fpga:
    rhashtable_destroy(&hq_table);
    return ret;
}

static void __exit hq_mod_exit(void) {
    // Unregister the interface
    interface_unregister();

    // Remove the debugfs directory
    debugfs_remove_recursive(debugfs);

    // Remove kprobes
    kprobes_remove();

    // Remove syscall hooks
    tracepoints_remove();

    // Cleanup FPGA
    fpga_finish();

    // Delete all contexts
    rhashtable_free_and_destroy(&hq_table, free_hq_context, (void *)1);
}

module_init(hq_mod_init);
module_exit(hq_mod_exit);
