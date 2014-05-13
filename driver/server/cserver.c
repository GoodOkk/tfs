#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cdrom.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/cdev.h>

#include <asm/uaccess.h>

#include <klog.h>
#include <cserver.h>

MODULE_LICENSE("GPL");

#define __SUBCOMPONENT__ "csrv"

static int __init csrv_init(void)
{	
	int error = -EINVAL;
	
	error = klog_init();
	if (error) {
		printk(KERN_ERR "klog_init failed with err=%d", error);
		goto out;
	}


	klog(KL_INFO, "init");
out:
	return error;
}

static void __exit csrv_exit(void)
{
	klog(KL_INFO, "exiting");
	klog(KL_INFO, "exited");
	klog_release();
}

module_init(csrv_init);
module_exit(csrv_exit);

