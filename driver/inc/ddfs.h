#pragma once

#include <linux/fs.h>

struct ddfs_super_block {
	__le32 			magic;	
};

struct ddfs_sb_info {
	struct ddfs_super_block *sb;
	struct buffer_head	*sbh;		
	spinlock_t		lock;
	int 			blocksize;	
};

#define DDFS_SUPER_MAGIC 0x31415926
