#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/signal.h>
#include <linux/stat.h>

#include "hq.h"
#include "interface-stats.h"
#include "interface.h"

#include "config.h"
#include "messages-verifier.h"
#include "messages.h"

/* Internal variables */
static dev_t major;
static struct class *cl;
static struct cdev cdev[INTERFACE_NUM_DEVICES];

/* Initialization/cleanup functions */
static int interface_uevent(struct device *dev, struct kobj_uevent_env *env) {
    // Only grant RW to owner
    add_uevent_var(env, "DEVMODE=%#o", S_IRUSR | S_IWUSR);
    return 0;
}

int interface_register() {
    int i, ret;
    struct device *dev;

    // Register a region of character device numbers
    if ((ret = alloc_chrdev_region(&major, 0, INTERFACE_NUM_DEVICES,
                                   INTERFACE_DEVICE_NAME))) {
        pr_warn("Creating character device region " INTERFACE_DEVICE_NAME
                " failed!\n");
        return ret;
    }

    // Create the device class
    cl = class_create(THIS_MODULE, HQ_CLASS_NAME);
    if (IS_ERR(cl)) {
        pr_warn("Creating device class " HQ_CLASS_NAME " failed!\n");
        ret = PTR_ERR(cl);
        goto err_class;
    }
    cl->dev_uevent = interface_uevent;

    for (i = 0; i < INTERFACE_NUM_DEVICES; ++i) {
        // Create the character device
        cdev_init(&cdev[i], &verifier_interface_fops);
        if ((ret = cdev_add(&cdev[i], MKDEV(MAJOR(major), i), 1))) {
            pr_warn("Creating character device %d failed!\n", i);
            goto err_cdev;
        }

        // Create the device
        dev = device_create(cl, NULL, MKDEV(MAJOR(major), i), NULL,
                            INTERFACE_DEVICE_NAME "-%d", i);
        if (IS_ERR(dev)) {
            pr_warn("Creating device " INTERFACE_DEVICE_NAME "-%d failed!\n",
                    i);
            ret = PTR_ERR(dev);
            goto err_dev;
        }

        pr_info("Created device " INTERFACE_DEVICE_NAME "-%d.\n", i);
    }

    if ((ret = interface_stats_register())) {
        pr_warn("Creating statistics failed!\n");
        goto err_stats;
    }

    return ret;

err_stats:
    i = 0;
    while (i >= 0) {
        device_destroy(cl, MKDEV(MAJOR(major), i));
    err_dev:
        cdev_del(&cdev[i]);
    err_cdev:
        --i;
    }
    class_destroy(cl);
err_class:
    unregister_chrdev_region(major, INTERFACE_NUM_DEVICES);
    return ret;
}

void interface_unregister() {
    unsigned i;

    interface_stats_unregister();

    for (i = 0; i < INTERFACE_NUM_DEVICES; ++i) {
        device_destroy(cl, MKDEV(MAJOR(major), i));
        cdev_del(&cdev[i]);
        pr_info("Removed device " INTERFACE_DEVICE_NAME "-%d.\n", i);
    }

    class_destroy(cl);
    unregister_chrdev_region(major, INTERFACE_NUM_DEVICES);
}
