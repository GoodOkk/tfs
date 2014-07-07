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

#include <tfs_misc.h>
#include <tfs_srv.h>
#include <tfs_cmd.h>
#include <tfs_private.h>
#include <klog.h>

MODULE_LICENSE("GPL");

#define __SUBCOMPONENT__ "tfs_main"
#define __LOGNAME__ "tfs.log"

#define SECTOR_SHIFT		9
#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)


#define SECTOR_SIZE  (PAGE_SIZE/PAGE_SECTORS)

static struct tfs_sb_info *tfs_sb_info_create(struct super_block *sb)
{
	struct tfs_sb_info *si = NULL;
	si = kzalloc(sizeof(struct tfs_sb_info), GFP_KERNEL);
	if (!si) {
		klog(KL_ERR, "kzalloc failed");
		return NULL;
	}
	spin_lock_init(&si->lock);

	return si;
}

static void tfs_sb_info_free(struct tfs_sb_info *si)
{
	if (si->sbh)
		brelse(si->sbh);
	kfree(si);	
}

static struct inode *tfs_alloc_inode(struct super_block *sb)
{
	struct tfs_inode_info *ini = NULL;
	ini = (struct tfs_inode_info *)kzalloc(sizeof(struct tfs_inode_info), GFP_KERNEL);
	if (!ini) {
		klog(KL_ERR, "cant alloc inode info");
		return NULL;
	}
	return &ini->vfs_inode;
}

static void tfs_inode_rcu_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct tfs_inode_info *ini = container_of(inode, struct tfs_inode_info, vfs_inode);
	
	kfree(ini);
}

static void tfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, tfs_inode_rcu_callback);
}

static int tfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	klog(KL_INFO, "dentry=%p, buf=%p", dentry, buf);
	return 0;
}

static int tfs_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	klog(KL_INFO, "sb=%p, flags=%p, data=%p", sb, flags, data);
	return 0;
}

static void tfs_put_super(struct super_block *sb)
{
	struct tfs_sb_info *si = sb->s_fs_info;

	klog(KL_INFO, "sb=%p, si=%p", sb, si);

	if (si) {
		if (si->sbh)
			mark_buffer_dirty(si->sbh);
		tfs_sb_info_free(si);
	}
	sb->s_fs_info = NULL;
}

static const struct super_operations tfs_super_ops = {
	.alloc_inode = tfs_alloc_inode,
	.destroy_inode = tfs_destroy_inode,
	.put_super = tfs_put_super,
	.statfs = tfs_statfs,
	.remount_fs = tfs_remount,
};

static int tfs_fill_super(struct super_block *sb, void *data, int silent)
{
	int err = -EINVAL;
	struct tfs_sb_info *si = NULL;
	struct tfs_super_block *dsb = NULL;
	unsigned long offset = 0;

	klog(KL_INFO, "sb=%p, data=%p, silent=%d", sb, data, silent);
	
	si = tfs_sb_info_create(sb);
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
	dsb = (struct tfs_super_block *)(((char *)si->sbh->b_data) + offset);
	si->sb = dsb;
	sb->s_magic = le32_to_cpu(dsb->magic);
	if (sb->s_magic != TFS_SUPER_MAGIC) {
		klog(KL_ERR, "cant fount tfs magic");
		goto out_si_free;
	}			
	sb->s_maxbytes = MAX_LFS_FILESIZE;

out_si_free:
	sb->s_fs_info = NULL;
	tfs_sb_info_free(si);

	return err;
}

static void tfs_kill_sb(struct super_block *sb)
{
	klog(KL_INFO, "sb=%p", sb);
	kill_block_super(sb);
}

static struct dentry *tfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	klog(KL_INFO, "fs_type=%p, flags=%x, dev_name=%s, data=%p",
		fs_type, flags, dev_name, data);

	return mount_bdev(fs_type, flags, dev_name, data, tfs_fill_super);
}

static struct file_system_type tfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "tfs",
	.mount = tfs_mount,
	.kill_sb = tfs_kill_sb,
	.fs_flags = FS_REQUIRES_DEV,
};

static int __init tfs_init(void)
{	
	int err = -EINVAL;
	
	err = klog_init();
	if (err) {
		printk(KERN_ERR "klog_init failed with err=%d", err);
		goto out;
	}

	err = tfs_srv_init();
	if (err) {
		klog(KL_ERR, "tfs_srv_init err=%d", err);
		goto out_klog_release;
	}

	err = tfs_misc_register();
	if (err) {
		klog(KL_ERR, "tfs_misc_register err=%d", err);
		goto out_srv_release;
	}
	
	err = register_filesystem(&tfs_fs_type);
	if (err) {
		klog(KL_ERR, "register_filesystem err=%d", err);
		goto out_misc_unreg; 
	}
	klog(KL_INFO, "module loaded");
	return 0;

out_misc_unreg:
	tfs_misc_deregister();
out_srv_release:
	tfs_srv_exit();		
out_klog_release:
	klog_release();
out:
	return err;
}

static void __exit tfs_exit(void)
{
	klog(KL_INFO, "unregistering fs");
	unregister_filesystem(&tfs_fs_type);
	klog(KL_INFO, "unregistering misc device");
	tfs_misc_deregister();
	klog(KL_INFO, "shutdowning server");
	tfs_srv_exit();
	klog(KL_INFO, "exited");
	klog_release();
}

module_init(tfs_init);
module_exit(tfs_exit);

