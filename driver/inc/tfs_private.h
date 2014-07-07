#pragma once

#include <linux/fs.h>
#include <linux/vfs.h>

#include <tfs_public.h>

struct tfs_inode_info {
	struct inode vfs_inode;
};

struct tfs_sb_info {
	struct tfs_super_block *sb;
	struct buffer_head	*sbh;		
	spinlock_t		lock;
	int 			blocksize;	
};

