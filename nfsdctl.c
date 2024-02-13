#include <linux/module.h>
#include <linux/version.h>
#include <netlink/genl/genl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>

#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/netlink.h>

#include "nfsdctl.h"

/* compile note:
 * gcc -I/usr/include/libnl3/ -o <prog-name> <prog-name>.c -lnl-3 -lnl-genl-3
 */

#define NFSD4_OPS_MAX_LEN	sizeof(nfsd4_ops) / sizeof(nfsd4_ops[0])
static const char* nfsd4_ops[] = {
	[OP_ACCESS]		= "OP_ACCESS",
	[OP_CLOSE]		= "OP_CLOSE",
	[OP_COMMIT]		= "OP_COMMIT",
	[OP_CREATE]		= "OP_CREATE",
	[OP_DELEGRETURN]	= "OP_DELEGRETURN",
	[OP_GETATTR]		= "OP_GETATTR",
	[OP_GETFH]		= "OP_GETFH",
	[OP_LINK]		= "OP_LINK",
	[OP_LOCK]		= "OP_LOCK",
	[OP_LOCKT]		= "OP_LOCKT",
	[OP_LOCKU]		= "OP_LOCKU",
	[OP_LOOKUP]		= "OP_LOOKUP",
	[OP_LOOKUPP]		= "OP_LOOKUPP",
	[OP_NVERIFY]		= "OP_NVERIFY",
	[OP_OPEN]		= "OP_OPEN",
	[OP_OPEN_CONFIRM]	= "OP_OPEN_CONFIRM",
	[OP_OPEN_DOWNGRADE]	= "OP_OPEN_DOWNGRADE",
	[OP_PUTFH]		= "OP_PUTFH",
	[OP_PUTPUBFH]		= "OP_PUTPUBFH",
	[OP_PUTROOTFH]		= "OP_PUTROOTFH",
	[OP_READ]		= "OP_READ",
	[OP_READDIR]		= "OP_READDIR",
	[OP_READLINK]		= "OP_READLINK",
	[OP_REMOVE]		= "OP_REMOVE",
	[OP_RENAME]		= "OP_RENAME",
	[OP_RENEW]		= "OP_RENEW",
	[OP_RESTOREFH]		= "OP_RESTOREFH",
	[OP_SAVEFH]		= "OP_SAVEFH",
	[OP_SECINFO]		= "OP_SECINFO",
	[OP_SETATTR]		= "OP_SETATTR",
	[OP_SETCLIENTID]	= "OP_SETCLIENTID",
	[OP_SETCLIENTID_CONFIRM] = "OP_SETCLIENTID_CONFIRM",
	[OP_VERIFY]		= "OP_VERIFY",
	[OP_WRITE]		= "OP_WRITE",
	[OP_RELEASE_LOCKOWNER]	= "OP_RELEASE_LOCKOWNER",
	/* NFSv4.1 operations */
	[OP_EXCHANGE_ID]	= "OP_EXCHANGE_ID",
	[OP_BACKCHANNEL_CTL]	= "OP_BACKCHANNEL_CTL",
	[OP_BIND_CONN_TO_SESSION] = "OP_BIND_CONN_TO_SESSION",
	[OP_CREATE_SESSION]	= "OP_CREATE_SESSION",
	[OP_DESTROY_SESSION]	= "OP_DESTROY_SESSION",
	[OP_SEQUENCE]		= "OP_SEQUENCE",
	[OP_DESTROY_CLIENTID]	= "OP_DESTROY_CLIENTID",
	[OP_RECLAIM_COMPLETE]	= "OP_RECLAIM_COMPLETE",
	[OP_SECINFO_NO_NAME]	= "OP_SECINFO_NO_NAME",
	[OP_TEST_STATEID]	= "OP_TEST_STATEID",
	[OP_FREE_STATEID]	= "OP_FREE_STATEID",
	[OP_GETDEVICEINFO]	= "OP_GETDEVICEINFO",
	[OP_LAYOUTGET]		= "OP_LAYOUTGET",
	[OP_LAYOUTCOMMIT]	= "OP_LAYOUTCOMMIT",
	[OP_LAYOUTRETURN]	= "OP_LAYOUTRETURN",
	/* NFSv4.2 operations */
	[OP_ALLOCATE]		= "OP_ALLOCATE",
	[OP_DEALLOCATE]		= "OP_DEALLOCATE",
	[OP_CLONE]		= "OP_CLONE",
	[OP_COPY]		= "OP_COPY",
	[OP_READ_PLUS]		= "OP_READ_PLUS",
	[OP_SEEK]		= "OP_SEEK",
	[OP_OFFLOAD_STATUS]	= "OP_OFFLOAD_STATUS",
	[OP_OFFLOAD_CANCEL]	= "OP_OFFLOAD_CANCEL",
	[OP_COPY_NOTIFY]	= "OP_COPY_NOTIFY",
	[OP_GETXATTR]		= "OP_GETXATTR",
	[OP_SETXATTR]		= "OP_SETXATTR",
	[OP_LISTXATTRS]		= "OP_LISTXATTRS",
	[OP_REMOVEXATTR]	= "OP_REMOVEXATTR",
};

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;

	*ret = err->error;
	return NL_SKIP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	*ret = 0;
	return NL_STOP;
}

static void parse_rpc_status_get(struct genlmsghdr *gnlh)
{
	struct nlattr *attr;
	int rem;

	nla_for_each_attr(attr, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), rem) {
		switch (nla_type(attr)) {
		case NFSD_A_RPC_STATUS_XID:
		case NFSD_A_RPC_STATUS_FLAGS:
			printf(" 0x%08x", nla_get_u32(attr));
			break;
		case NFSD_A_RPC_STATUS_PROC:
		case NFSD_A_RPC_STATUS_PROG:
			printf(" %d", nla_get_u32(attr));
			break;
		case NFSD_A_RPC_STATUS_VERSION:
			printf(" NFS%d", nla_get_u8(attr));
			break;
		case NFSD_A_RPC_STATUS_SERVICE_TIME:
			printf(" %ld", nla_get_u64(attr));
			break;
		case NFSD_A_RPC_STATUS_DADDR4:
		case NFSD_A_RPC_STATUS_SADDR4: {
			struct in_addr addr = {
				.s_addr = nla_get_u32(attr),
			};

			printf(" %s", inet_ntoa(addr));
			break;
		}
		case NFSD_A_RPC_STATUS_DPORT:
		case NFSD_A_RPC_STATUS_SPORT:
			printf(" %hu", nla_get_u16(attr));
			break;
		case NFSD_A_RPC_STATUS_COMPOUND_OPS: {
			unsigned int op = nla_get_u32(attr);

			if (op < NFSD4_OPS_MAX_LEN)
				printf(" %s", nfsd4_ops[op]);
			break;
		}
		default:
			break;
		}
	}
	printf("\n");
}

static void parse_version_get(struct genlmsghdr *gnlh)
{
	struct nlattr *attr;
	int rem;

	printf("Server Versions:");
	nla_for_each_attr(attr, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), rem) {
		struct nlattr *a;
		int i;

		nla_for_each_nested(a, attr, i) {
			switch (nla_type(a)) {
			case NFSD_A_VERSION_MAJOR:
				printf("\t%d", nla_get_u32(a));
				break;
			case NFSD_A_VERSION_MINOR:
				printf(":%d", nla_get_u32(a));
				break;
			default:
				break;
			}
		}
	}
	printf("\n");
}

static void parse_listener_get(struct genlmsghdr *gnlh)
{
	int rem, major, minor;
	struct nlattr *attr;

	printf("Server Listeners:");
	nla_for_each_attr(attr, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), rem) {
		unsigned short proto = 0;
		const char *name = NULL;
		unsigned port = 0;
		struct nlattr *a;
		int i;

		nla_for_each_nested(a, attr, i) {
			switch (nla_type(a)) {
			case NFSD_A_LISTENER_TRANSPORT_NAME:
				name = nla_data(a);
				break;
			case NFSD_A_LISTENER_PORT:
				port = nla_get_u32(a);
				break;
			case NFSD_A_LISTENER_INET_PROTO:
				proto = nla_get_u16(a);
				break;
			default:
				break;
			}
		}

		if (name && port && proto)
			printf("\n\t%s%s:%d",
			       name, proto == AF_INET6 ? "6" : "4", port);
	}
	printf("\n");
}

static int recv_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	const struct nlattr *attr = genlmsg_attrdata(gnlh, 0);

	switch (gnlh->cmd) {
	case NFSD_CMD_RPC_STATUS_GET:
		parse_rpc_status_get(gnlh);
		break;
	case NFSD_CMD_THREADS_GET:
		if (nla_type(attr) == NFSD_A_SERVER_WORKER_THREADS)
			printf("Running threads\t: %d\n", nla_get_u32(attr));
		break;
	case NFSD_CMD_VERSION_GET:
		parse_version_get(gnlh);
		break;
	case NFSD_CMD_LISTENER_GET:
		parse_listener_get(gnlh);
		break;
	default:
		break;
	}

	return NL_SKIP;
}

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h'		},
	{ "rpc-status", no_argument, NULL, 'R'		},
	{ "set-threads", required_argument, NULL, 't'	},
	{ "get-threads", no_argument, NULL, 'T'		},
	{ "set-version", required_argument, NULL, 'v'	},
	{ "get-versions", no_argument, NULL, 'V'	},
	{ "set-sockaddr", required_argument, NULL, 's'	},
	{ "set-listener", required_argument, NULL, 'p'	},
	{ "get-listeners", no_argument, NULL, 'P'	},
	{ },
};

static int get_cmd_type(int arg)
{
	switch (arg) {
	case 'R':
		return NFSD_CMD_RPC_STATUS_GET;
	case 't':
		return NFSD_CMD_THREADS_SET;
	case 'T':
		return NFSD_CMD_THREADS_GET;
	case 'v':
		return NFSD_CMD_VERSION_SET;
	case 'V':
		return NFSD_CMD_VERSION_GET;
	case 'p':
		return NFSD_CMD_LISTENER_SET;
	case 'P':
		return NFSD_CMD_LISTENER_GET;
	case 's':
		return NFSD_CMD_SOCK_SET;
	case 'h':
	default:
		return -EINVAL;
	}
}

static void usage(char *argv[], const struct option *long_options)
{
	int i;

	printf("\nOption for %s:\n", argv[0]);
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-15s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value: %d)",
			       *long_options[i].flag);
		else
			printf("\t short-option: -%c", long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

#define BUFFER_SIZE	8192
static void *nl_sock_and_msg_alloc(struct nl_sock **psock, struct nl_msg **pmsg)
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	int ret, id;
	void *hdr;

	sock = nl_socket_alloc();
	if (!sock)
		return NULL;

	if (genl_connect(sock)) {
		fprintf(stderr, "Failed to connect to generic netlink\n");
		nl_socket_free(sock);
		return NULL;
	}

	nl_socket_set_buffer_size(sock, BUFFER_SIZE, BUFFER_SIZE);
	setsockopt(nl_socket_get_fd(sock), SOL_NETLINK, NETLINK_EXT_ACK,
		   &ret, sizeof(ret));

	id = genl_ctrl_resolve(sock, NFSD_FAMILY_NAME);
	if (id < 0) {
		fprintf(stderr, "%s not found\n", NFSD_FAMILY_NAME);
		nl_socket_free(sock);
		return NULL;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		nl_socket_free(sock);
		return NULL;
	}

	hdr = genlmsg_put(msg, 0, 0, id, 0, 0, 0, 0);
	if (!hdr) {
		fprintf(stderr, "failed to allocate netlink message\n");
		nl_socket_free(sock);
		nlmsg_free(msg);
		return NULL;
	}

	*psock = sock;
	*pmsg = msg;

	return hdr - GENL_HDRLEN;
}

int main(char argc, char **argv)
{
	int port, proto, nl_cmd = 0, longindex = 0, opt, ret = 1;
	char transport[64], addr[64];
	struct nl_sock *sock = NULL;
	struct nl_msg *msg = NULL;
	struct genlmsghdr *ghdr;
	struct nl_cb *cb;

	if (argc == 1) {
		usage(argv, long_options);
		return -EINVAL;
	}

	ghdr = nl_sock_and_msg_alloc(&sock, &msg);
	if (!ghdr)
		return -ENOMEM;

	ret = EINVAL;
	while ((opt = getopt_long(argc, argv, "Rt:Tv:Vp:Ps:h",
				  long_options, &longindex)) != -1) {
		int cmd = get_cmd_type(opt);

		if (cmd < 0) {
			usage(argv, long_options);
			goto out;
		}

		if (nl_cmd && cmd != nl_cmd) {
			usage(argv, long_options);
			goto out;
		}

		nl_cmd = cmd;
		switch (nl_cmd) {
		case NFSD_CMD_RPC_STATUS_GET: {
			struct nlmsghdr *nlh = (void *)ghdr - NLMSG_HDRLEN;

			nlh->nlmsg_flags |= NLM_F_DUMP;
			break;
		}
		case NFSD_CMD_THREADS_SET: {
			int thread = strtoul(optarg, NULL, 0);

			nla_put_u32(msg, NFSD_A_SERVER_WORKER_THREADS, thread);
			break;
		}
		case NFSD_CMD_VERSION_SET: {
			struct nlattr *a;
			int major, minor;

			if (sscanf(optarg, "%d.%d", &major, &minor) != 2) {
				usage(argv, long_options);
				goto out;
			}


			a = nla_nest_start(msg,
					   NLA_F_NESTED | NFSD_A_SERVER_PROTO_VERSION);
			if (!a) {
				ret = -ENOMEM;
				goto out;
			}

			nla_put_u32(msg, NFSD_A_VERSION_MAJOR, major);
			nla_put_u32(msg, NFSD_A_VERSION_MINOR, minor);
			nla_nest_end(msg, a);
			break;
		}
		case NFSD_CMD_LISTENER_SET: {
			struct nlattr *a;

			if (sscanf(optarg, "%s.%d.%d",
				   transport, &port, &proto) != 3) {
				usage(argv, long_options);
				goto out;
			}


			a = nla_nest_start(msg,
					   NLA_F_NESTED | NFSD_A_SERVER_LISTENER_INSTANCE);
			if (!a) {
				ret = -ENOMEM;
				goto out;
			}
			nla_put_string(msg, NFSD_A_LISTENER_TRANSPORT_NAME,
				       transport);
			nla_put_u32(msg, NFSD_A_LISTENER_PORT, port);
			nla_put_u16(msg, NFSD_A_LISTENER_INET_PROTO, proto);
			nla_nest_end(msg, a);
			break;
		}
		case NFSD_CMD_SOCK_SET: {
			struct sockaddr_storage sa_storage = {};
			struct nlattr *a;

			if (sscanf(optarg, "[%s].%s.%d.%d",
				   addr, &port, transport, &proto) != 4) {
				usage(argv, long_options);
				goto out;
			}

			switch (proto) {
			case AF_INET: {
				struct sockaddr_in *sin = (void *)&sa_storage;

				sin->sin_family = AF_INET;
				sin->sin_port = htons(port);
				if (inet_pton(AF_INET, addr,
					      &sin->sin_addr) != 1) {
					ret = -EINVAL;
					goto out;
				}
				break;
			}
			case AF_INET6: {
				struct sockaddr_in6 *sin6 = (void *)&sa_storage;

				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = htons(port);
				if (inet_pton(AF_INET6, addr,
					      &sin6->sin6_addr) != 1) {
					ret = -EINVAL;
					goto out;
				}
				break;
			}
			default:
				ret = -EINVAL;
				goto out;
			}

			a = nla_nest_start(msg,
					   NLA_F_NESTED | NFSD_A_SERVER_SOCK_ADDR);
			if (!a) {
				ret = -ENOMEM;
				goto out_cb;
			}
			nla_put(msg, NFSD_A_SOCK_ADDR, sizeof(sa_storage),
				&sa_storage);
			nla_put_string(msg, NFSD_A_SOCK_TRANSPORT_NAME,
				       transport);
			nla_nest_end(msg, a);
			break;
		}
		default:
			break;
		}
	}
	ghdr->cmd = nl_cmd;

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = nl_send_auto_complete(sock, msg);
	if (ret < 0)
		goto out_cb;

	ret = 1;
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &ret);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, recv_handler, NULL);

	while (ret > 0)
		nl_recvmsgs(sock, cb);
out_cb:
	nl_cb_put(cb);
out:
	if (ret)
		nlmsg_free(msg);
	nl_socket_free(sock);
	return ret;
}
