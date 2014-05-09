obj-m += cdisk_mod.o
ccflags-y := -I$(src)/include -I$(src)/inc

cdisk_mod-y := cdisk.o klog.o sockets.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	cp cdisk_mod.ko ../bin/cdisk_mod.ko
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -r -f ../bin/cdisk_mod.ko
