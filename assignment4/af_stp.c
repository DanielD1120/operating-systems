// SPDX-License-Identifier: GPL-2.0+

/*
 * af_stp.c - Transport protocol
 *
 * Author: Daniel Dinca <dincadaniel97@gmail.com>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include "stp.h"

static struct proc_dir_entry *stp_proc_entry;

static struct stp_socket {
	struct sock sk;
};

static struct proto my_proto = {
	.obj_size = sizeof(struct stp_socket),
	.name = STP_PROTO_NAME,
	.owner = THIS_MODULE,
};

static struct data {
	int r;
	int h;
	int c;
	int n1;
	int n2;
	int t;
} stp_data;

static int stp_proc_show(struct seq_file *m, void *v)
{
	seq_puts(m, "RxPkts HdrErr CsumErr NoSock NoBuffs TxPkts\n");
	seq_printf(m, "%d %d %d %d %d %d\n",
			stp_data.r, stp_data.h, stp_data.c,
			stp_data.n1, stp_data.n2, stp_data.t);

	return 0;
}

static int stp_proc_open(struct inode *inode, struct  file *file)
{
	return single_open(file, stp_proc_show, NULL);
}

static const struct file_operations r_fops = {
	.owner		= THIS_MODULE,
	.open		= stp_proc_open,
	.read		= seq_read,
	.release	= single_release,
};

static int stp_release(struct socket *sock)
{
	sock_put(sock->sk);

	return 0;
}

static int stp_bind(struct socket *sock,
				struct sockaddr *myaddr,
				int sockaddr_len)
{
	return 0;
}

static int stp_connect(struct socket *sock,
						struct sockaddr *vaddr,
						int sockaddr_len,
						int flags)
{
	return 0;
}

static int stp_sendmsg(struct socket *sock,
					   struct msghdr *m,
					   size_t total_len)
{
	return 0;
}

static int stp_recvmsg(struct socket *sock,
					   struct msghdr *m,
					   size_t total_len,
					   int flags)
{
	return 0;
}

static const struct proto_ops stp_ops = {
		.family = PF_STP,
		.owner = THIS_MODULE,
		.release = stp_release,
		.bind = stp_bind,
		.connect = stp_connect,
		.socketpair = sock_no_socketpair,
		.accept = sock_no_accept,
		.getname = sock_no_getname,
		.poll = datagram_poll,
		.ioctl = sock_no_ioctl,
		.listen = sock_no_listen,
		.shutdown = sock_no_shutdown,
		.setsockopt = sock_no_setsockopt,
		.getsockopt = sock_no_getsockopt,
		.sendmsg = stp_sendmsg,
		.recvmsg = stp_recvmsg,
		.mmap = sock_no_mmap,
		.sendpage = sock_no_sendpage,
};

static int my_create_socket(struct net *net,
							struct socket *sock,
							int protocol,
							int kern)
{
	struct sock *sk;

	if (sock->type != SOCK_DGRAM || protocol != 0)
		return -ESOCKTNOSUPPORT;

	sk = sk_alloc(net, AF_STP, GFP_KERNEL, &my_proto, kern);
	if (!sk) {
		pr_err("sk_alloc failed");
		return -ENOMEM;
	}

	sock_init_data(sock, sk);
	sk->sk_protocol = protocol;
	sk->sk_family = AF_STP;
	sock->ops = &stp_ops;

	return 0;
};

struct net_proto_family my_net_proto = {
	.family = AF_STP,
	.create = my_create_socket,
	.owner = THIS_MODULE,
};

static int stp_init(void)
{
	int err;

	stp_proc_entry = proc_create(STP_PROC_NET_FILENAME,
					0000, init_net.proc_net, &r_fops);
	if (!stp_proc_entry) {
		err = -ENOMEM;
		goto out;
	}

	err = proto_register(&my_proto, 0);
	if (err < 0) {
		pr_err("proto register failed, returned %d\n", err);
		goto remove_proc;
	}

	err = sock_register(&my_net_proto);
	if (err < 0) {
		pr_err("sock register failed, returned %d\n", err);
		goto remove_proto;
	}

	return 0;

remove_proto:
	proto_unregister(&my_proto);
remove_proc:
	proc_remove(stp_proc_entry);
out:
	return err;
}

static void stp_exit(void)
{
	proc_remove(stp_proc_entry);
	proto_unregister(&my_proto);
	sock_unregister(AF_STP);
}

module_init(stp_init);
module_exit(stp_exit);

MODULE_DESCRIPTION("Transport protocol");
MODULE_AUTHOR("Daniel Dinca <dincadaniel97@gmail.com>");
MODULE_LICENSE("GPL v2");
