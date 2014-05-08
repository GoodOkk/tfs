#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>
#include <errno.h>
#include <malloc.h>

#include <cdisk_cmd.h>


static void usage(void)
{
    	printf("cdisk_ctl --create\n");
}

static int cdisk_ctl_open(int *fd)
{
	int dev_fd = -1;
	int error = -EINVAL;

	dev_fd = open("/dev/cdisk0", 0);
	if (dev_fd == -1) {
		error = errno;
		printf("cant open ctl disk device, error=%d\n", error);
		return error;
	}
	*fd = dev_fd;
	return 0;
}

static int cdisk_create(int *disk_num)
{
	int error = -EINVAL;
	int fd = -1;
	struct cdisk_params params;

	error = cdisk_ctl_open(&fd);
	if (error)
		return error;
	
	memset(&params, 0, sizeof(struct cdisk_params));

	error = ioctl(fd, IOCTL_DISK_CREATE, &params);
	if (error)
		goto out;
	
	*disk_num = params.u.create.disk_num;
out:
	close(fd);
	return error;
}

#define CREATE_OPT "--create"

int main(int argc, char *argv[])
{
    	int error = -EINVAL;
    
    	if (argc != 2) {
    		usage();
    	    	error = -EINVAL;
		goto out;
    	}
    
    	if (strncmp(argv[1], CREATE_OPT, strlen(CREATE_OPT) + 1) == 0) {
		int disk_num = -1;
		error = cdisk_create(&disk_num);
		if (!error)
			printf("created disk with num=%d\n", disk_num);
		goto out;
    	} else {
		usage();
		error = -EINVAL;
		goto out;
	}

out:
	if (error)
		printf("error - %d\n", error);

	return error;
}

