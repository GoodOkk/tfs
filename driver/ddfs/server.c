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


#include <ddfs_srv.h>
#include <ddfs_cmd.h>
#include <klog.h>
#include <ksocket.h>

#define __SUBCOMPONENT__ "ddfs_srv"
#define __LOGNAME__ "ddfs_srv.log"

#define LISTEN_RESTART_TIMEOUT_MS 5000

static struct task_struct *ddfs_srv_thread;

static struct socket *ddfs_srv_sock = NULL;

static DEFINE_MUTEX(ddfs_srv_lock);

static int ddfs_srv_stopping = 0;

static LIST_HEAD(con_list);
static DEFINE_MUTEX(con_list_lock);

struct ddfs_srv_con {
	struct task_struct 	*thread;
	struct socket 		*sock;
	struct list_head	con_list;
};

static void ddfs_srv_con_wait(struct ddfs_srv_con *con)
{
	kthread_stop(con->thread);
}

static void ddfs_srv_con_free(struct ddfs_srv_con *con)
{
	klog(KL_DEBUG, "releasing sock %p", con->sock);
	ksock_release(con->sock);
	put_task_struct(con->thread);
	kfree(con);
}

static int ddfs_srv_con_thread_routine(void *data)
{
	struct ddfs_srv_con *con = (struct ddfs_srv_con *)data;
	BUG_ON(con->thread != current);

	klog(KL_DEBUG, "inside con thread %p, sock %p", con->thread, con->sock);


	klog(KL_DEBUG, "closing sock %p", con->sock);
	if (!ddfs_srv_stopping) {
		mutex_lock(&con_list_lock);
		if (!list_empty(&con->con_list))
			list_del_init(&con->con_list);	
		else
			con = NULL;
		mutex_unlock(&con_list_lock);

		if (con)
			ddfs_srv_con_free(con);
	}

	return 0;
}

static struct ddfs_srv_con *ddfs_srv_con_start(struct socket *sock)
{
	struct ddfs_srv_con *con = kmalloc(sizeof(struct ddfs_srv_con), GFP_KERNEL);
	int err = -EINVAL;
	if (!con) {
		klog(KL_ERR, "cant alloc ddfs_srv_con");
		return NULL;
	}

	con->thread = NULL;
	con->sock = sock;
	con->thread = kthread_create(ddfs_srv_con_thread_routine, con, "ddfs_srv_con");
	if (IS_ERR(con->thread)) {
		err = PTR_ERR(con->thread);
		klog(KL_ERR, "kthread_create err=%d", err);
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

static int ddfs_srv_thread_routine(void *data)
{
	struct socket *lsock = NULL;
	struct socket *con_sock = NULL;
	struct ddfs_srv_con *con = NULL;
	int err = 0;

	while (!kthread_should_stop()) {
		if (!ddfs_srv_sock) {
			err = ksock_listen(&lsock, INADDR_ANY, 9111, 5);
			if (err) {
				klog(KL_ERR, "csock_listen err=%d", err);
				msleep_interruptible(LISTEN_RESTART_TIMEOUT_MS);
				continue;
			} else {
				mutex_lock(&ddfs_srv_lock);
				ddfs_srv_sock = lsock;
				mutex_unlock(&ddfs_srv_lock);
			}
		}

		if (ddfs_srv_sock && !ddfs_srv_stopping) {
			klog(KL_DEBUG, "accepting");
			err = ksock_accept(&con_sock, ddfs_srv_sock);
			if (err) {
				if (err == -EAGAIN)
					klog(KL_WARN, "csock_accept err=%d", err);
				else
					klog(KL_ERR, "csock_accept err=%d", err);
				continue;
			}
			klog(KL_DEBUG, "accepted con_sock=%p", con_sock);

			if (!ddfs_srv_con_start(con_sock)) {
				klog(KL_ERR, "ddfs_srv_con_start failed");
				ksock_release(con_sock);
				continue;
			}
		}
	}

	err = 0;
	klog(KL_INFO, "releasing listen socket");
	
	mutex_lock(&ddfs_srv_lock);
	lsock = ddfs_srv_sock;
	ddfs_srv_sock = NULL;
	mutex_unlock(&ddfs_srv_lock);

	if (lsock)
		ksock_release(lsock);
	
	klog(KL_INFO, "releasing cons");

	for (;;) {
		con = NULL;
		mutex_lock(&con_list_lock);
		if (!list_empty(&con_list)) {
			con = list_first_entry(&con_list, struct ddfs_srv_con, con_list);
			list_del_init(&con->con_list);		
		}
		mutex_unlock(&con_list_lock);
		if (!con)
			break;

		ddfs_srv_con_wait(con);
		ddfs_srv_con_free(con);
	}

	klog(KL_INFO, "released cons");	
	return 0;
}

int ddfs_srv_init(void)
{	
	int err = -EINVAL;

	klog(KL_INFO, "initing");

	ddfs_srv_thread = kthread_create(ddfs_srv_thread_routine, NULL, "ddfs_srv");
	if (IS_ERR(ddfs_srv_thread)) {
		err = PTR_ERR(ddfs_srv_thread);
		klog(KL_ERR, "kthread_create err=%d", err);
		goto out;
	}
	get_task_struct(ddfs_srv_thread);
	wake_up_process(ddfs_srv_thread);

	klog(KL_INFO, "inited");
	return 0;
out:
	return err;
}

void ddfs_srv_exit(void)
{
	klog(KL_INFO, "exiting");
	
	ddfs_srv_stopping = 1;

	mutex_lock(&ddfs_srv_lock);
	if (ddfs_srv_sock)
		ksock_abort_accept(ddfs_srv_sock);
	mutex_unlock(&ddfs_srv_lock);

	kthread_stop(ddfs_srv_thread);
	put_task_struct(ddfs_srv_thread);

	klog(KL_INFO, "exited");
}
