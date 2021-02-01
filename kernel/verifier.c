#include <linux/delay.h>
#include <linux/kfifo.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/rhashtable.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include <asm/pgtable.h>

#include "hq-interface.h"
#include "hq.h"
#include "verifier.h"

#include "config.h"
#include "interfaces.h"
#include "messages-verifier.h"

/* Function declarations */
static ssize_t interface_verifier_read(struct file *fp, char *buf, size_t len,
                                       loff_t *off);
static int interface_verifier_mmap(struct file *fp, struct vm_area_struct *vma);
static int interface_verifier_open(struct inode *ip, struct file *fp);
static int interface_verifier_release(struct inode *ip, struct file *fp);

/* Internal variables */
const struct file_operations verifier_interface_fops = {
    .owner = THIS_MODULE,
    .read = interface_verifier_read,
    .mmap = interface_verifier_mmap,
    .open = interface_verifier_open,
    .release = interface_verifier_release,
};

#ifdef CONFIG_HAVE_IOREMAP_PROT
const struct vm_operations_struct verifier_vma_ops = {
    .access = generic_access_phys,
};
#endif /* CONFIG_HAVE_IOREMAP_PROT */

// Waitqueue for messages that must be delivered before resuming
DECLARE_WAIT_QUEUE_HEAD(wq);

// Notify page for the verifier
static struct hq_verifier_notify *verifier;

// Message buffer queue for the verifier
DEFINE_KFIFO(msg_fifo, struct hq_verifier_msg, VERIFIER_MSG_FIFO_SIZE);
// Memory mapping queue for the verifier
DEFINE_KFIFO(map_fifo, void *, VERIFIER_MSG_FIFO_SIZE);

// Lock on message queues to ensure single-producer, and to prevent reordering
// between both queues
DEFINE_SPINLOCK(fifo_lock);

static int send_message(struct hq_verifier_msg *msg, void *ptr, bool wait) {
    int ret = 0;
    unsigned long flags;

    if (!verifier)
        return -ENODEV;

    spin_lock_irqsave(&fifo_lock, flags);

    // Check both FIFOs are not full
    if (kfifo_is_full(&msg_fifo) || (ptr && kfifo_is_full(&map_fifo))) {
        ret = -ENOSPC;
        goto out;
    }

    // Check either both insertions succeeded or failed
    if (kfifo_put(&msg_fifo, *msg) != (ptr ? kfifo_put(&map_fifo, ptr) : 1))
        ret = -ENOSPC;

    atomic_set((atomic_t *)&verifier->pending, kfifo_len(&msg_fifo));
out:
    spin_unlock_irqrestore(&fifo_lock, flags);

    if (!ret && wait) {
        // Ignore return value; handle killed processes normally
        if (wait_event_killable(wq, kfifo_is_empty(&msg_fifo))) {
            pr_warn("Interrupted by signal in tgid %d!\n", msg->pid);
        }
    }

    return ret;
}

/* Function implementations */
int verifier_is_connected(void) { return !!verifier; }

int verifier_interface_on_clone(pid_t ppid, struct hq_ctx *ctx) {
    int ret = 0;
#ifdef HQ_CHECK_SYSCALL
    void *map = ctx->syscall;
#else
    void *map = NULL;
#endif /* HQ_CHECK_SYSCALL */
    struct hq_verifier_msg msg = {
        .pid = ppid,
        .op = HQ_VERIFIER_MSG_CLONE,
        .value = ctx->tgid,
    };

    if ((ret = send_message(&msg, map, true)))
        pr_warn("Error while appending CLONE, dropping verifier message!\n");

    return ret;
}

int verifier_interface_on_exit(pid_t pid) {
    int ret = 0;
    struct hq_verifier_msg msg = {
        .pid = pid,
        .op = HQ_VERIFIER_MSG_TERMINATE,
    };

    if ((ret = send_message(&msg, NULL, false)))
        pr_warn(
            "Error while appending TERMINATE, dropping verifier message!\n");

    return ret;
}

int verifier_interface_notify(pid_t pid, struct hq_ctx *ctx) {
    int ret = 0;
#ifdef HQ_CHECK_SYSCALL
    void *map = ctx->syscall;
#else
    void *map = NULL;
#endif /* HQ_CHECK_SYSCALL */
    struct hq_verifier_msg msg = {
        .pid = pid,
        .op = HQ_VERIFIER_MSG_SYSCALL_PAGE,
    };

    if ((ret = send_message(&msg, map, true)))
        pr_warn(
            "Error while appending SYSCALL_PAGE, dropping verifier message!\n");

    return ret;
}

/* Filesystem operations */
static ssize_t interface_verifier_read(struct file *fp, char *buf, size_t len,
                                       loff_t *off) {
    int ret;
    unsigned long flags;
    unsigned int copied, rem;

    if (!verifier)
        return -ENXIO;
    if (len < sizeof(struct hq_verifier_msg))
        return -EINVAL;

    spin_lock_irqsave(&fifo_lock, flags);

    ret = kfifo_to_user(&msg_fifo, buf, len, &copied);
    rem = kfifo_len(&msg_fifo);
    atomic_set((atomic_t *)&verifier->pending, rem);

    spin_unlock_irqrestore(&fifo_lock, flags);
    if (!rem)
        wake_up(&wq);
    return ret ? ret : copied;
}

static int interface_verifier_mmap(struct file *fp,
                                   struct vm_area_struct *vma) {
    void *ptr;
    size_t len = vma->vm_end - vma->vm_start;

    // Check the mapping arguments are valid
    if (vma->vm_end <= vma->vm_start || len != SYSCALL_MAP_SIZE ||
        (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) != VM_WRITE ||
        vma->vm_pgoff)
        return -EINVAL;

    // Get the next mapping
    if (!kfifo_get(&map_fifo, &ptr))
        return -EINVAL;

    // Ensure the mapping flags are correct
    vma->vm_flags = (vma->vm_flags &
                     ~(VM_MERGEABLE | VM_HUGEPAGE | VM_HUGETLB | VM_MAYEXEC)) |
                    VM_DONTCOPY | VM_DONTEXPAND | VM_SHARED;

    // Support debug access to the mapping
#ifdef CONFIG_HAVE_IOREMAP_PROT
    vma->vm_ops = &verifier_vma_ops;
#endif /* CONFIG_HAVE_IOREMAP_PROT */

    // Map the physical page(s)
    return remap_pfn_range(vma, vma->vm_start, virt_to_phys(ptr) >> PAGE_SHIFT,
                           len, vma->vm_page_prot);
}

static int interface_verifier_open(struct inode *ip, struct file *fp) {
    int ret = 0;
    struct hq_verifier_msg msg = {
        .pid = 0,
        .op = HQ_VERIFIER_MSG_NOTIFY,
    };

    if (verifier)
        return -EBUSY;
    // Reuse the system call page size
    verifier = (struct hq_verifier_notify *)__get_free_pages(
        GFP_KERNEL | __GFP_ZERO, get_order(SYSCALL_MAP_SIZE));

    if ((ret = send_message(&msg, verifier, false))) {
        pr_warn("Error while appending NOTIFY, dropping verifier message!\n");
        return ret;
    }

    return nonseekable_open(ip, fp);
}

static int interface_verifier_release(struct inode *ip, struct file *fp) {
    struct rhashtable_iter iter;
    struct hq_ctx *app;
    unsigned long flags;

    WARN_ON(!verifier);

    free_pages((unsigned long)verifier, get_order(SYSCALL_MAP_SIZE));
    verifier = NULL;

    // Clear the FIFOs
    spin_lock_irqsave(&fifo_lock, flags);
    kfifo_reset(&msg_fifo);
    kfifo_reset(&map_fifo);
    spin_unlock_irqrestore(&fifo_lock, flags);

    // Clear the rhashtable
    rhashtable_walk_enter(&hq_table, &iter);
    rhashtable_walk_start(&iter);
    while ((app = rhashtable_walk_next(&iter))) {
        if (IS_ERR(app)) {
            if (PTR_ERR(app) == -EAGAIN)
                continue;
            pr_warn("Cannot access context entry %p while walking hashtable!\n",
                    app);
            break;
        }

#ifdef HQ_PRESERVE_STATS
        free_hq_context(app, NULL);
#else
        if (rhashtable_remove_fast(&hq_table, &app->node, hq_params)) {
            pr_warn("Cannot remove context for tgid %d!\n", app->tgid);
            continue;
        }

        free_hq_context(app, (void *)1);
#endif /* HQ_PRESERVE_STATS */
    }
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    wake_up(&wq);
    return 0;
}
