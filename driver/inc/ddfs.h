#pragma once

#include <linux/fs.h>
#include <linux/vfs.h>


#define DDFS_ROOT_INO 0

struct ddfs_inode_info {
	struct inode vfs_inode;
};

struct ddfs_inode {
	__le16	mode;
	__le16 	nlinks;
	__le16	uid;
	__le16 	gid;
	__le32	size;
	__le32	atime;
	__le32	mtime;
	__le32	ctime;
};

struct ddfs_super_block {
	__le32 			magic;
	__le32			state;
};

struct ddfs_sb_info {
	struct ddfs_super_block *sb;
	struct buffer_head	*sbh;		
	spinlock_t		lock;
	int 			blocksize;	
};

#define DDFS_SUPER_MAGIC 0x31415926
