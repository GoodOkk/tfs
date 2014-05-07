obj-m += cdisk_mod.o
ccflags-y := -I$(src)/include -I$(src)/inc

cdisk_mod-y := cdisk.o klog.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

