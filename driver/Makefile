obj-m = tfs.o

ccflags-y := -I$(src)/include -I$(src)/inc -g3 -Wall -Werror

tfs-y := src/main.o src/misc_ioctl.o src/server.o lib/klog.o lib/ksocket.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	cp tfs.ko ../bin/tfs.ko
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -r -f ../bin/tfs.ko
