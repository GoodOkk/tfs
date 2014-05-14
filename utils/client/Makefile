CC=gcc
CFLAGS=-c -Wall -Werror -I../../driver/include

all: cd_cli_ctl
	cp cd_cli_ctl ../../bin/cd_cli_ctl

cd_cli_ctl: cd_cli_ctl.o
	$(CC) cd_cli_ctl.o -o cd_cli_ctl

cd_cli_ctl.o: cd_cli_ctl.c
	$(CC) $(CFLAGS) cd_cli_ctl.c

clean:
	rm -rf *.o cd_cli_ctl
	rm -r -f ../../bin/cd_cli_ctl

