#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>
#include <errno.h>
#include <malloc.h>

#include <driver/linux/include/cdisk_cmd.h>


void usage()
{
    	printf("cdisk_ctl -d DEVNAME\n");
}

int main(int argc, char *argv[])
{
    	int fd = -1;
    	char *devname = NULL;
    	int result = -1;
    
    	if (argc != 3) {
    	    usage();
    	    return -1;
    	}
    
    	if (strncmp(argv[1], "-d", strlen("-d") + 1) != 0) {
    	    usage();
    	    return -1;
    	}
    
    	devname = argv[2];
    	fd = open(devname, 0);
    	if (fd == -1) {
    	    printf("device %s not opened error=%d\n", devname, errno); 
    	    return -1;
    	}
    	printf("device %s opened fd=%d\n", devname, fd);
    
	result = ioctl(fd, IOCTL_HELLO, 0);
	printf("ioctl result=%d\n", result);


    	if (fd != -1)
        	close(fd);
	return result;
}

