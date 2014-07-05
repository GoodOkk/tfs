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
#include <linux/vfs.h>
#include <linux/mount.h>
#include <linux/buffer_head.h>
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

static struct ddfs_sb_info *ddfs_sb_info_create(struct super_block *sb)
{
	struct ddfs_sb_info *si = NULL;
	si = kzalloc(sizeof(struct ddfs_sb_info), GFP_KERNEL);
	if (!si) {
		klog(KL_ERR, "kzalloc failed");
		return NULL;
	}
	spin_lock_init(&si->lock);

	return si;
}

static void ddfs_sb_info_free(struct ddfs_sb_info *si)
{
	if (si->sbh)
		brelse(si->sbh);
	kfree(si);	
}

static int ddfs_fill_super(struct super_block *sb, void *data, int silent)
{
	int err = -EINVAL;
	struct ddfs_sb_info *si = NULL;
	struct ddfs_super_block *dsb = NULL;
	unsigned long offset = 0;

	klog(KL_INFO, "sb=%p, data=%p, silent=%d", sb, data, silent);
	
	si = ddfs_sb_info_create(sb);
	if (!si) {
		klog(KL_ERR, "cant create sb info for sb=%p", sb);
		return err; 
	}
	si->blocksize = sb_min_blocksize(sb, BLOCK_SIZE);	
	if (!si->blocksize) {
		klog(KL_ERR, "block_size is 0");
		goto out_si_free;
	}
	sb->s_fs_info = si;
	si->sbh = sb_bread(sb, 0);
	if (!si->sbh) {
		klog(KL_ERR, "unable to read superblock");
		goto out_si_free;
	}
	dsb = (struct ddfs_super_block *)(((char *)si->sbh->b_data) + offset);
	si->sb = dsb;
	sb->s_magic = le32_to_cpu(dsb->magic);
	if (sb->s_magic != DDFS_SUPER_MAGIC) {
		klog(KL_ERR, "cant fount ddfs magic");
		goto out_si_free;
	}			
	sb->s_maxbytes = MAX_LFS_FILESIZE;

out_si_free:
	sb->s_fs_info = NULL;
	ddfs_sb_info_free(si);

	return err;
}

static void ddfs_kill_sb(struct super_block *sb)
{
	klog(KL_INFO, "sb=%p", sb);
	kill_block_super(sb);
}

static struct dentry *ddfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	klog(KL_INFO, "fs_type=%p, flags=%x, dev_name=%s, data=%p",
		fs_type, flags, dev_name, data);

	return mount_bdev(fs_type, flags, dev_name, data, ddfs_fill_super);
}

static struct file_system_type ddfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "ddfs",
	.mount = ddfs_mount,
	.kill_sb = ddfs_kill_sb,
	.fs_flags = FS_REQUIRES_DEV,
};

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
	
	err = register_filesystem(&ddfs_fs_type);
	if (err) {
		klog(KL_ERR, "register_filesystem err=%d", err);
		goto out_misc_unreg; 
	}
	klog(KL_INFO, "module loaded");
	return 0;

out_misc_unreg:
	ddfs_misc_deregister();
out_srv_release:
	ddfs_srv_exit();		
out_klog_release:
	klog_release();
out:
	return err;
}

static void __exit ddfs_exit(void)
{
	klog(KL_INFO, "unregistering fs");
	unregister_filesystem(&ddfs_fs_type);
	klog(KL_INFO, "unregistering misc device");
	ddfs_misc_deregister();
	klog(KL_INFO, "shutdowning server");
	ddfs_srv_exit();
	klog(KL_INFO, "exited");
	klog_release();
}

module_init(ddfs_init);
module_exit(ddfs_exit);

