/*
*/

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

#include <ddfs_misc.h>
#include <ddfs_srv.h>
#include <ddfs_cmd.h>
#include <ddfs.h>
#include <klog.h>

MODULE_LICENSE("GPL");

#define __SUBCOMPONENT__ "ddfs"
#define __LOGNAME__ "ddfs.log"

#define SECTOR_SHIFT		9
#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)


#define SECTOR_SIZE  (PAGE_SIZE/PAGE_SECTORS)

static int __init ddfs_init(void)
{	
	int err = -EINVAL;
	
	err = klog_init();
	if (err) {
		printk(KERN_ERR "klog_init failed with err=%d", err);
		goto out;
	}

	err = ddfs_srv_init();
	if (err) {
		klog(KL_ERR, "ddfs_srv_init err=%d", err);
		goto out_klog_release;
	}

	err = ddfs_misc_register();
	if (err) {
		klog(KL_ERR, "ddfs_misc_register err=%d", err);
		goto out_srv_release;
	}

	klog(KL_INFO, "module loaded");
	return 0;

out_srv_release:
	ddfs_srv_exit();		
out_klog_release:
	klog_release();
out:
	return err;
}

static void __exit ddfs_exit(void)
{
	klog(KL_INFO, "exiting");
	ddfs_misc_deregister();
	klog(KL_INFO, "going exit server");
	ddfs_srv_exit();
	klog(KL_INFO, "server stopped");
	klog(KL_INFO, "exited");
	klog_release();
}

module_init(ddfs_init);
module_exit(ddfs_exit);

