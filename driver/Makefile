obj-m = ddfs.o

ccflags-y := -I$(src)/include -I$(src)/inc -g3 -Wall -Werror

ddfs-y := ddfs/main.o ddfs/misc_ioctl.o ddfs/server.o lib/klog.o lib/ksocket.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	cp ddfs.ko ../bin/ddfs.ko
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -r -f ../bin/ddfs.ko
