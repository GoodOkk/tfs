#pragma once
#include <linux/ioctl.h>

#define IOC_MAGIC 0xED000000

#define IOCTL_DDFS_SETUP	_IO(IOC_MAGIC, 1)

#pragma pack(push, 1)

#define DDFS_IOCTL_NAME "ddfs_ctl"

struct ddfs_cmd {
	int error;
	union {
		struct {
			int reserved;
		} setup;
	} u;
};

#pragma pack(pop)
