#pragma once
#include <linux/ioctl.h>

#define IOC_TFS_MAGIC 0xED000000

#define IOCTL_TFS_SETUP	_IO(IOC_TFS_MAGIC, 1)

#pragma pack(push, 1)

#define TFS_IOCTL_NAME "ddfs_ctl"

struct tfs_cmd {
	int error;
	union {
		struct {
			int reserved;
		} setup;
	} u;
};

#pragma pack(pop)
