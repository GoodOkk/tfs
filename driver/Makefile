obj-m = cdisk_cli.o cdisk_srv.o

ccflags-y := -I$(src)/include -I$(src)/inc -g3 -Wall -Werror

cdisk_cli-y := client/cdisk.o	lib/klog.o lib/socket.o
cdisk_srv-y := server/cserver.o	lib/klog.o lib/socket.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	cp cdisk_cli.ko ../bin/cdisk_cli.ko
	cp cdisk_srv.ko ../bin/cdisk_srv.ko

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -r -f ../bin/cdisk_cli.ko
	rm -r -f ../bin/cdisk_srv.ko

