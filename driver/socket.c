#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/ip.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <net/sock.h>

#include "socket.h"
#include "klog.h"

#include <cdisk.h>

#define __SUBCOMPONENT__ "socket"


int csock_create(struct socket **sockp,
	__u32 local_ip, int local_port)
{
	struct sockaddr_in 	localaddr;
	struct socket		*sock = NULL;
	int 			error;
	int 			option;
	
	error = sock_create(PF_INET, SOCK_STREAM, 0, &sock);
	if (error) {
		klog(KL_ERR, "sock_create err=%d", error);
		goto out;	
	}
	option = 1;
	error = sock_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		(char *)&option, sizeof(option));
	if (error) {
		klog(KL_ERR, "sock_setsockopt err=%d", error);
		goto out_sock_release;
	}
	if (local_ip != 0 || local_port != 0) {
		memset(&localaddr, 0, sizeof(localaddr));
		localaddr.sin_family = AF_INET;
		localaddr.sin_port = htons(local_port);
		localaddr.sin_addr.s_addr = (local_ip == 0) ? 
			INADDR_ANY : htonl(local_ip);
		error = sock->ops->bind(sock, (struct sockaddr *)&localaddr,
				sizeof(localaddr));
		if (error == -EADDRINUSE) {
			klog(KL_ERR, "port %d already in use", local_port);
			goto out_sock_release;
		}
		if (error) {
			klog(KL_ERR, "bind to port=%d err=%d", local_port, 
					error);
			goto out_sock_release;
		}
	}
	return 0;

out_sock_release:
	sock_release(sock);
out:
	return error;
}

int csock_set_sendbufsize(struct socket *sock, int size)
{
	int option = size;
	int error;

	error = sock_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
		(char *)&option, sizeof(option));
	if (error) {
		klog(KL_ERR, "cant set send buf size=%d for sock=%p",
			size, sock);
	}

	return error;
}

int csock_set_rcvbufsize(struct socket *sock, int size)
{
	int option = size;
	int error;

	error = sock_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
		(char *)&option, sizeof(option));
	if (error) {
		klog(KL_ERR, "cant set rcv buf size=%d for sock=%p",
			size, sock);
	}

	return error;
}

int csock_connect(struct socket **sockp, __u32 local_ip, int local_port,
			__u32 peer_ip, int peer_port)
{
	struct sockaddr_in srvaddr;
	int error;
	struct socket *sock = NULL;

	error = csock_create(&sock, local_ip, local_port);
	if (error) {
		klog(KL_ERR, "sock create failed with err=%d", error);
		goto out;
	}

	memset(&srvaddr, 0, sizeof(srvaddr));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(peer_port);
	srvaddr.sin_addr.s_addr = htonl(peer_ip);

	error = sock->ops->connect(sock, (struct sockaddr *)&srvaddr,
			sizeof(srvaddr), 0);
	if (error) {
		klog(KL_ERR, "connect failed with err=%d", error);
		goto out_sock_release;
	}
	*sockp = sock;
	return 0;

out_sock_release:
	sock_release(sock);
out:
	return error;
}

void csock_release(struct socket *sock)
{
	sock_release(sock);
}

int csock_write_timeout(struct socket *sock, void *buffer, int nob, int timeout, int *pwrote)
{
	int error;
	long ticks = timeout*HZ;
	unsigned long then;
	struct timeval tv;
	int wrote = 0;

	BUG_ON(nob <= 0);
	for (;;) {
		struct iovec iov = {
			.iov_base = buffer,
			.iov_len = nob
		};

		struct msghdr msg = {
			.msg_name = NULL,
			.msg_namelen = 0,
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = (ticks == 0) ? MSG_DONTWAIT : 0
		};
		
		if (ticks != 0) {
			tv = (struct timeval) {
				.tv_sec = ticks/HZ,
				.tv_usec = ((ticks % HZ) * 1000000)/HZ
			};
			error = sock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
					(char *)&tv, sizeof(tv));
			if (error) {
				klog(KL_ERR, "cant set sock timeout, err=%d",
					error);
				goto out;
			}
		}
		then = jiffies;
		error = sock_sendmsg(sock, &msg, iov.iov_len);
		ticks-= jiffies - then;

		if (error < 0) {
			klog(KL_ERR, "send err=%d", error);
			goto out;
		}

		if (error == 0) {
			klog(KL_ERR, "send returned zero size");
			error = -ECONNABORTED;
			goto out;
		}

		if (error > 0)
			wrote+= error;

		
		buffer = (void *)((unsigned long)buffer + error);
		nob-= error;
		if (nob == 0) {
			error = 0;
			goto out;
		}

		if (ticks <= 0) {
			klog(KL_ERR, "timeout reached");
			error = -EAGAIN;
			goto out;
		}
	}
out:
	if (pwrote)
		*pwrote = wrote;

	return error;
}

int csock_read_timeout(struct socket *sock, void *buffer, int nob, int timeout, int *pread)
{
	int error;
	long ticks = timeout*HZ;
	unsigned long then;
	struct timeval tv;
	int read = 0;

	BUG_ON(nob <= 0);
	BUG_ON(ticks <= 0);

	for (;;) {
		struct iovec iov = {
			.iov_base = buffer,
			.iov_len = nob
		};

		struct msghdr msg = {
			.msg_name = NULL,
			.msg_namelen = 0,
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = 0
		};
		
		
		tv = (struct timeval) {
			.tv_sec = ticks/HZ,
			.tv_usec = ((ticks % HZ) * 1000000)/HZ
		};

		error = sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
					(char *)&tv, sizeof(tv));
		if (error) {
			klog(KL_ERR, "cant set sock timeout, err=%d",
				error);
			goto out;
		}

		then = jiffies;
		error = sock_recvmsg(sock, &msg, iov.iov_len, 0);
		ticks-= jiffies - then;
		
		if (error < 0) {
			klog(KL_ERR, "recv err=%d", error);
			goto out;
		}
		
		if (error == 0) {
			klog(KL_ERR, "recv returned zero size");
			error = -ECONNRESET;
			goto out;
		}

		if (error > 0)
			read+= error;

		buffer = (void *)((unsigned long)buffer + error);
		nob-= error;
		if (nob == 0) {
			error = 0;
			goto out;
		}

		if (ticks <= 0) {
			klog(KL_ERR, "timeout reached");
			error = -ETIMEDOUT;
			goto out;
		}
	}
out:
	if (pread)
		*pread = read;
	return error;
}

