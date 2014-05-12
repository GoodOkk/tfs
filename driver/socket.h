#pragma once

#include <net/sock.h>

int csock_create(struct socket **sockp,
	__u32 local_ip, int local_port);

int csock_set_sendbufsize(struct socket *sock, int size);

int csock_set_rcvbufsize(struct socket *sock, int size);

int csock_connect(struct socket **sockp, __u32 local_ip, int local_port,
			__u32 peer_ip, int peer_port);

void csock_release(struct socket *sock);

int csock_write_timeout(struct socket *sock, void *buffer, int nob, int timeout, int *pwrote);

int csock_read_timeout(struct socket *sock, void *buffer, int nob, int timeout, int *pread);
