#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
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


#include <ddfs_misc.h>
#include <ddfs_cmd.h>
#include <klog.h>

#define __SUBCOMPONENT__ "klog"
#define __LOGNAME__ "ddfs_srv.log"

static long ddfs_misc_ioctl(struct file *file, unsigned int code, unsigned long arg)
{
	int error = -EINVAL;
	struct ddfs_cmd *cmd = NULL;	

	cmd = kmalloc(sizeof(struct ddfs_cmd), GFP_KERNEL);
	if (!cmd) {
		error = -ENOMEM;
		goto out;
	}

	if (copy_from_user(cmd, (const void *)arg, sizeof(struct ddfs_cmd))) {
		error = -EFAULT;
		goto out_free_cmd;
	}
	
	error = 0;
	switch (code) {
		case IOCTL_DDFS_SETUP:
			cmd->error = -EINVAL;
			break;
		default:
			klog(KL_ERR, "unknown ioctl=%d", cmd);
			error = -EINVAL;
			break;
	}
	
	if (copy_to_user((void *)arg, cmd, sizeof(struct ddfs_cmd))) {
		error = -EFAULT;
		goto out_free_cmd;
	}
	
	return 0;
out_free_cmd:
	kfree(cmd);
out:
	return error;	
}

static int ddfs_misc_open(struct inode *inode, struct file *file)
{
	klog(KL_INFO, "in open");
	if (!try_module_get(THIS_MODULE)) {
		klog(KL_ERR, "cant ref module");
		return -EINVAL;
	}
	klog(KL_INFO, "opened");
	return 0;
}

static int ddfs_misc_release(struct inode *inode, struct file *file)
{
	klog(KL_INFO, "in release");
	module_put(THIS_MODULE);
	klog(KL_INFO, "released");
	return 0;
}

static const struct file_operations ddfs_misc_fops = {
	.owner = THIS_MODULE,
	.open = ddfs_misc_open,
	.release = ddfs_misc_release,
	.unlocked_ioctl = ddfs_misc_ioctl,
};

static struct miscdevice ddfs_misc = {
	.fops = &ddfs_misc_fops,
	.minor = MISC_DYNAMIC_MINOR,
	.name = DDFS_IOCTL_NAME,	
};

int ddfs_misc_register()
{
	int err = -EINVAL;
	err = misc_register(&ddfs_misc);
	if (err) {
		klog(KL_ERR, "misc_register err=%d", err);
	}
	return err;
}

void ddfs_misc_deregister()
{
	misc_deregister(&ddfs_misc);
}
