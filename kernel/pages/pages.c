#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>

#include <asm/set_memory.h>

static unsigned memtype = 1;

typedef enum {
    WRITE_BACK,
    WRITE_COMBINING,
    WRITE_THROUGH,
    UNCACHED,
} memtype_t;

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Memory page allocator");
MODULE_VERSION("0.1");
module_param(memtype, int, 0444);
MODULE_PARM_DESC(memtype, "Type of memory mapping (0 = write-back, 1 = "
                          "write-combining, 2 = write-through, 3 = uncached");

#define CLASS_NAME "pages"
#define DEVICE_NAME "pages"
#define NUM_DEVICES 1

static const char STR_WB[] = "write-back", STR_WC[] = "write-combining",
                  STR_WT[] = "write-through", STR_UC[] = "uncached";

static dev_t major;
static struct class *cl;
static struct cdev cdev[NUM_DEVICES];

static int mmap(struct file *fp, struct vm_area_struct *vma) {
    pgprot_t type;
    size_t len = vma->vm_end - vma->vm_start;

    // Check the mapping arguments are valid
    if (vma->vm_end <= vma->vm_start || len > 2 * PAGE_SIZE || vma->vm_pgoff)
        return -EINVAL;

    switch (memtype) {
    case WRITE_COMBINING:
        type = pgprot_writecombine(vma->vm_page_prot);
        break;
    case WRITE_THROUGH:
        type = pgprot_writethrough(vma->vm_page_prot);
        break;
    case UNCACHED:
        type = pgprot_noncached(vma->vm_page_prot);
        break;
    default:
        type = vma->vm_page_prot;
        break;
    }
    // Map the physical page
    return remap_pfn_range(vma, vma->vm_start,
                           virt_to_phys(fp->private_data) >> PAGE_SHIFT, len,
                           type);
}

static int open(struct inode *ip, struct file *fp) {
    unsigned i;
    const char *str;
    struct page *pgs[2] = {0};
    // Allocate two physically contiguous pages (2^1), of order 1
    void *virt = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
    // Convenience functions (e.g. set_memory_wt) have been removed in 5.4.0+
    for (i = 0; i < 2; ++i)
        pgs[i] =
            pfn_to_page((virt_to_phys(virt) + i * PAGE_SIZE) >> PAGE_SHIFT);

    switch (memtype) {
    case WRITE_COMBINING:
        set_pages_array_wc(pgs, 2);
        str = STR_WC;
        break;
    case WRITE_THROUGH:
        set_pages_array_wt(pgs, 2);
        str = STR_WT;
        break;
    case UNCACHED:
        set_pages_array_uc(pgs, 2);
        str = STR_UC;
        break;
    default:
        set_pages_array_wb(pgs, 2);
        str = STR_WB;
        break;
    }

    fp->private_data = virt;
    pr_info("Allocated %s pages %pK!\n", str, fp->private_data);
    return nonseekable_open(ip, fp);
}

static int release(struct inode *ip, struct file *fp) {
    set_memory_wb((unsigned long)fp->private_data, 2);
    free_pages((unsigned long)fp->private_data, 1);
    pr_info("Freed pages %pK!\n", fp->private_data);
    return 0;
}

const struct file_operations fops = {
    .owner = THIS_MODULE,
    .mmap = mmap,
    .open = open,
    .release = release,
};

static int uevent(struct device *dev, struct kobj_uevent_env *env) {
    // Grant RW to all
    add_uevent_var(env, "DEVMODE=%#o", S_IRUGO | S_IWUGO);
    return 0;
}

static int __init mod_init(void) {
    struct device *dev;
    unsigned i;
    int ret;

    // Register a region of character device numbers
    if ((ret = alloc_chrdev_region(&major, 0, NUM_DEVICES, DEVICE_NAME))) {
        pr_warn("Creating character device region " DEVICE_NAME " failed!\n");
        return ret;
    }

    // Create the device class
    cl = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(cl)) {
        pr_warn("Creating device class " CLASS_NAME " failed!\n");
        ret = PTR_ERR(cl);
        goto err_class;
    }
    cl->dev_uevent = uevent;

    for (i = 0; i < NUM_DEVICES; ++i) {
        // Create the character device
        cdev_init(&cdev[i], &fops);
        if ((ret = cdev_add(&cdev[i], MKDEV(MAJOR(major), i), 1))) {
            pr_warn("Creating character device %d failed!\n", i);
            goto err_cdev;
        }

        // Create the device
        dev = device_create(cl, NULL, MKDEV(MAJOR(major), i), NULL,
                            DEVICE_NAME "-%d", i);
        if (IS_ERR(dev)) {
            pr_warn("Creating device " DEVICE_NAME "-%d failed!\n", i);
            ret = PTR_ERR(dev);
            goto err_dev;
        }

        pr_info("Created device " DEVICE_NAME "-%d.\n", i);
    }

    return ret;

    i = 0;
    while (i >= 0) {
    err_dev:
        cdev_del(&cdev[i]);
    err_cdev:
        --i;
    }
    class_destroy(cl);
err_class:
    unregister_chrdev_region(major, NUM_DEVICES);
    return ret;
}

static void __exit mod_exit(void) {
    unsigned i;

    for (i = 0; i < NUM_DEVICES; ++i) {
        device_destroy(cl, MKDEV(MAJOR(major), i));
        cdev_del(&cdev[i]);
        pr_info("Removed device " DEVICE_NAME "-%d.\n", i);
    }

    class_destroy(cl);
    unregister_chrdev_region(major, NUM_DEVICES);
}

module_init(mod_init);
module_exit(mod_exit);
