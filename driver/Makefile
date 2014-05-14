obj-m = cd_cli.o cd_srv.o

ccflags-y := -I$(src)/include -I$(src)/inc -g3 -Wall -Werror

cd_cli-y := client/cd_cli.o lib/klog.o lib/ksocket.o
cd_srv-y := server/cd_srv.o lib/klog.o lib/ksocket.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	cp cd_cli.ko ../bin/cd_cli.ko
	cp cd_srv.ko ../bin/cd_srv.ko

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -r -f ../bin/cd_cli.ko
	rm -r -f ../bin/cd_srv.ko

