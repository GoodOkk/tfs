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
#include <linux/delay.h>
#include <asm/uaccess.h>

#include <klog.h>
#include <socket.h>
#include <cserver.h>

MODULE_LICENSE("GPL");

#define __SUBCOMPONENT__ "csrv"


#define LISTEN_RESTART_TIMEOUT_MS 5000

static struct task_struct *csrv_thread;

static struct socket *csrv_sock = NULL;

static DEFINE_MUTEX(csrv_lock);

static int csrv_stopping = 0;

static LIST_HEAD(con_list);
static DEFINE_MUTEX(con_list_lock);

struct csrv_con {
	struct task_struct 	*thread;
	struct socket 		*sock;
	struct list_head	con_list;
};

static void csrv_con_wait(struct csrv_con *con)
{
	kthread_stop(con->thread);
}

static void csrv_con_free(struct csrv_con *con)
{
	klog(KL_DEBUG, "releasing sock %p", con->sock);
	sock_release(con->sock);
	put_task_struct(con->thread);
	kfree(con);
}

static int csrv_con_thread_routine(void *data)
{
	struct csrv_con *con = (struct csrv_con *)data;
	BUG_ON(con->thread != current);

	klog(KL_DEBUG, "inside con thread %p, sock %p", con->thread, con->sock);


	klog(KL_DEBUG, "closing sock %p", con->sock);
	if (!csrv_stopping) {
		mutex_lock(&con_list_lock);
		if (!list_empty(&con->con_list))
			list_del_init(&con->con_list);	
		else
			con = NULL;
		mutex_unlock(&con_list_lock);

		if (con)
			csrv_con_free(con);
	}

	return 0;
}

static struct csrv_con *csrv_con_start(struct socket *sock)
{
	struct csrv_con *con = kmalloc(sizeof(struct csrv_con), GFP_KERNEL);
	int error = -EINVAL;
	if (!con) {
		klog(KL_ERR, "cant alloc csrv_con");
		return NULL;
	}

	con->thread = NULL;
	con->sock = sock;
	con->thread = kthread_create(csrv_con_thread_routine, con, "cdisk_srv_con");
	if (IS_ERR(con->thread)) {
		error = PTR_ERR(con->thread);
		klog(KL_ERR, "kthread_create err=%d", error);
		goto out;
	}

	get_task_struct(con->thread);	
	mutex_lock(&con_list_lock);
	list_add_tail(&con->con_list, &con_list);
	mutex_unlock(&con_list_lock);

	wake_up_process(con->thread);

	return con;	
out:
	kfree(con);
	return NULL;
}

static int csrv_thread_routine(void *data)
{
	struct socket *lsock = NULL;
	struct socket *con_sock = NULL;
	struct csrv_con *con = NULL;
	int error = 0;

	while (!kthread_should_stop()) {
		if (!csrv_sock) {
			error = csock_listen(&lsock, INADDR_ANY, 9111, 5);
			if (error) {
				klog(KL_ERR, "csock_listen err=%d", error);
				msleep_interruptible(LISTEN_RESTART_TIMEOUT_MS);
				continue;
			} else {
				mutex_lock(&csrv_lock);
				csrv_sock = lsock;
				mutex_unlock(&csrv_lock);
			}
		}

		if (csrv_sock && !csrv_stopping) {
			klog(KL_DEBUG, "accepting");
			error = csock_accept(&con_sock, csrv_sock);
			if (error) {
				if (error == -EAGAIN)
					klog(KL_WARN, "csock_accept err=%d", error);
				else
					klog(KL_ERR, "csock_accept err=%d", error);
				continue;
			}
			klog(KL_DEBUG, "accepted con_sock=%p", con_sock);

			if (!csrv_con_start(con_sock)) {
				klog(KL_ERR, "csrv_con_start failed");
				csock_release(con_sock);
				continue;
			}
		}
	}

	error = 0;
	klog(KL_INFO, "releasing listen socket");
	
	mutex_lock(&csrv_lock);
	lsock = csrv_sock;
	csrv_sock = NULL;
	mutex_unlock(&csrv_lock);

	if (lsock)
		csock_release(lsock);
	
	klog(KL_INFO, "releasing cons");

	for (;;) {
		con = NULL;
		mutex_lock(&con_list_lock);
		if (!list_empty(&con_list)) {
			con = list_first_entry(&con_list, struct csrv_con, con_list);
			list_del_init(&con->con_list);		
		}
		mutex_unlock(&con_list_lock);
		if (!con)
			break;

		csrv_con_wait(con);
		csrv_con_free(con);
	}

	klog(KL_INFO, "released cons");	
	return 0;
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

	csrv_thread = kthread_create(csrv_thread_routine, NULL, "cdisk_srv");
	if (IS_ERR(csrv_thread)) {
		error = PTR_ERR(csrv_thread);
		klog(KL_ERR, "kthread_create err=%d", error);
		goto out_klog_release;
	}
	get_task_struct(csrv_thread);
	wake_up_process(csrv_thread);

	klog(KL_INFO, "inited");
	return 0;

out_klog_release:
	klog_release();
out:
	return error;
}

static void __exit csrv_exit(void)
{
	klog(KL_INFO, "exiting");
	
	csrv_stopping = 1;

	mutex_lock(&csrv_lock);
	if (csrv_sock)
		csock_abort_accept(csrv_sock);
	mutex_unlock(&csrv_lock);

	kthread_stop(csrv_thread);
	put_task_struct(csrv_thread);

	klog(KL_INFO, "exited");
	klog_release();
}

module_init(csrv_init);
module_exit(csrv_exit);

