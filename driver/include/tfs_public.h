#pragma once

#include <linux/fs.h>
#include <linux/vfs.h>

#define TFS_ROOT_INO 0

struct tfs_inode {
	__le16	mode;
	__le16 	nlinks;
	__le16	uid;
	__le16 	gid;
	__le32	size;
	__le32	atime;
	__le32	mtime;
	__le32	ctime;
};

struct tfs_super_block {
	__le32 			magic;
	__le32			state;
};

#define TFS_SUPER_MAGIC 0x31415926
