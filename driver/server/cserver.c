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
#include <linux/kthread.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <asm/uaccess.h>

#include <klog.h>
#include <socket.h>
#include <cserver.h>

MODULE_LICENSE("GPL");

#define __SUBCOMPONENT__ "csrv"

static struct task_struct *csrv_thread;

static int csrv_thread_routine(void *data)
{
	struct socket *lsock = NULL;
	int error = 0;

	while (!kthread_should_stop()) {
		error = csock_listen(&lsock, 0x00000000, 9111, 5);
		if (error) {
			klog(KL_ERR, "csock_listen err=%d", error);
			goto out;
		}
	}

out:
	if (lsock)
		csock_release(lsock);

	return error;
}


static int __init csrv_init(void)
{	
	int error = -EINVAL;
	
	error = klog_init();
	if (error) {
		printk(KERN_ERR "klog_init failed with err=%d", error);
		goto out;
	}

	klog(KL_INFO, "initing");

	csrv_thread = kthread_create(csrv_thread_routine, NULL, "kcdisk_srv");
	if (IS_ERR(csrv_thread)) {
		error = PTR_ERR(csrv_thread);
		klog(KL_ERR, "kthread_create err=%d", error);
		goto out_klog_release;
	}
	wake_up_process(csrv_thread);

	klog(KL_INFO, "inited");
out_klog_release:
	klog_release();
out:
	return error;
}

static void __exit csrv_exit(void)
{
	klog(KL_INFO, "exiting");
	kthread_stop(csrv_thread);
	klog(KL_INFO, "exited");
	klog_release();
}

module_init(csrv_init);
module_exit(csrv_exit);

