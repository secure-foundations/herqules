#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/ratelimit.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "hq-interface.h"
#include "hq.h"
#include "interface-stats.h"
#include "interface.h"

#include "interfaces.h"
#include "stats.h"

#define HQ_STATISTICS_NAME "statistics"

/* Declarations */
static int interface_stats_open(struct inode *ip, struct file *fp);
static ssize_t interface_stats_read(struct file *fp, char *buf, size_t len,
                                    loff_t *off);
static int interface_stats_release(struct inode *ip, struct file *fp);

/* Per-fd stats buffer */
struct stats_info {
    char buffer[4 * PAGE_SIZE];
    size_t size;
};

/* Internal variables */
static struct file_operations stats_fops = {
    .owner = THIS_MODULE,
    .open = interface_stats_open,
    .read = interface_stats_read,
    .release = interface_stats_release,
};

static struct dentry *debugfs_stats;

/* Implementation of statistics functions */
#define print_helper(app, stats, ret, out, f, ...)                             \
    ret = f(&stats->buffer[stats->size], sizeof(stats->buffer) - stats->size,  \
            __VA_ARGS__);                                                      \
    if (ret < 0) {                                                             \
        pr_warn_ratelimited("Error printing statistics for tgid %d!\n",        \
                            app ? app->tgid : -1);                             \
        goto out;                                                              \
    } else if (ret >= sizeof(stats->buffer) - stats->size) {                   \
        pr_warn_ratelimited(                                                   \
            "Filled buffer while printing statistics for tgid %d!\n",          \
            app ? app->tgid : -1);                                             \
        stats->size = sizeof(stats->buffer) - 1;                               \
        goto out;                                                              \
    } else                                                                     \
        stats->size += ret;

static int interface_stats_open(struct inode *ip, struct file *fp) {
    struct stats_info *stats;
    struct hq_ctx *app;
    struct rhashtable_iter iter;
    int ret;

    if (!(stats = kmalloc(sizeof(*stats), GFP_KERNEL)))
        return -ENOMEM;

    stats->size = 0;

    /* Print row headers */
    print_helper(app, stats, ret, out, snprintf, "name,tgid");

#define HQ_STAT(x) print_helper(app, stats, ret, out, snprintf, "," #x)
    HQ_STATS_LIST
#undef HQ_STAT
    print_helper(app, stats, ret, out, snprintf, "\n")

    /* Print each row */
    rhashtable_walk_enter(&hq_table, &iter);
    rhashtable_walk_start(&iter);
    while ((app = rhashtable_walk_next(&iter))) {
        if (IS_ERR(app)) {
            ret = PTR_ERR(app);
            if (ret == -EAGAIN)
                continue;
            pr_warn("Cannot access context %p while walking hashtable!\n", app);
            break;
        }

        print_helper(app, stats, ret, out, snprintf, "%s,%d", app->name,
                     app->tgid);

#define HQ_STAT(x)                                                             \
        print_helper(app, stats, ret, out, snprintf, ",%u",                    \
                     atomic_read(&app->stats[HQ_STAT_##x]))
        HQ_STATS_LIST
#undef HQ_STAT

        print_helper(app, stats, ret, out, snprintf, "\n")
    }

    print_helper(app, stats, ret, out, snprintf, "\n");

out:
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    fp->private_data = stats;
    return 0;
}

static ssize_t interface_stats_read(struct file *fp, char *buf, size_t len,
                                    loff_t *off) {
    struct stats_info *stats = fp->private_data;
    size_t bytes;

    BUG_ON(!fp->private_data);
    bytes = min((size_t)(stats->size - *off), len);

    if (bytes) {
        if (copy_to_user(buf, stats->buffer + *off, bytes))
            return -EFAULT;

        *off += bytes;
    }

    return bytes;
}

static int interface_stats_release(struct inode *ip, struct file *fp) {
    BUG_ON(!fp->private_data);

    kfree(fp->private_data);
    return 0;
}

int interface_stats_register(void) {
    int ret = 0;

    debugfs_stats = debugfs_create_file(HQ_STATISTICS_NAME, S_IRUGO, debugfs,
                                        NULL, &stats_fops);
    if (IS_ERR(debugfs_stats)) {
        pr_warn("Creation of debugfs file " HQ_STATISTICS_NAME " failed!\n");
        ret = PTR_ERR(debugfs_stats);
        goto out;
    }

out:
    return ret;
}

void interface_stats_unregister(void) { debugfs_remove(debugfs_stats); }
