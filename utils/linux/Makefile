CC=gcc
CFLAGS=-c -Wall -Werror -I../../

all: cdisk_ctl

cdiskctl: cdisk_ctl.o
	$(CC) cdisk_ctl.o -o cdisk_ctl

cdisk_ctl.o: cdisk_ctl.c
	$(CC) $(CFLAGS) cdisk_ctl.c

clean:
	rm -rf *.o cdisk_ctl

