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

#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/netlink.h>

/* compile note:
 * gcc -I/usr/include/libnl3/ -o <prog-name> <prog-name>.c -lnl-3 -lnl-genl-3
 */

#define SERVER_NAME	"nfsd_server"
#define BUFFER_SIZE	8192

static volatile bool exiting;

enum nfs_commands {
	NFS_CMD_UNSPEC,

	NFS_CMD_GET_RPC_STATUS,
	NFS_CMD_NEW_RPC_STATUS,

	/* add new commands above here */

	__NFS_CMD_MAX,
	NFS_CMD_MAX = __NFS_CMD_MAX - 1,
};

enum nfs_rcp_status_compound_attrs {
	__NFS_ATTR_RPC_STATUS_COMPOUND_INVALID,
	NFS_ATTR_RPC_STATUS_COMPOUND_OP,

	/* keep it last */
	NUM_NFS_ATTR_RPC_STATUS_COMPOUND,
	NFS_ATTR_RPC_STATUS_COMPOUND_MAX = NUM_NFS_ATTR_RPC_STATUS_COMPOUND - 1,
};

enum nfs_rpc_status_attrs {
	__NFS_ATTR_RPC_STATUS_INVALID,

	NFS_ATTR_RPC_STATUS_XID,
	NFS_ATTR_RPC_STATUS_FLAGS,
	NFS_ATTR_RPC_STATUS_PC_NAME,
	NFS_ATTR_RPC_STATUS_VERSION,
	NFS_ATTR_RPC_STATUS_STIME,
	NFS_ATTR_RPC_STATUS_SADDR4,
	NFS_ATTR_RPC_STATUS_DADDR4,
	NFS_ATTR_RPC_STATUS_SADDR6,
	NFS_ATTR_RPC_STATUS_DADDR6,
	NFS_ATTR_RPC_STATUS_SPORT,
	NFS_ATTR_RPC_STATUS_DPORT,
	NFS_ATTR_RPC_STATUS_PAD,
	NFS_ATTR_RPC_STATUS_COMPOUND,

	/* keep it last */
	NUM_NFS_ATTR_RPC_STATUS,
	NFS_ATTR_RPC_STATUS_MAX = NUM_NFS_ATTR_RPC_STATUS - 1,
};

enum nfs_attrs {
	NFS_ATTR_UNSPEC,

	NFS_ATTR_RPC_STATUS,

	/* add new attributes above here */

	__NFS_ATTR_MAX,
	NFS_ATTR_MAX = __NFS_ATTR_MAX - 1
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

static int recv_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NFS_ATTR_MAX + 1], *rpc_attr;
	int m;

	nla_parse(tb, NFS_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NFS_ATTR_RPC_STATUS]) {
		fprintf(stderr, "rpc status attr missing\n");
		return NL_SKIP;
	}

	nla_for_each_nested(rpc_attr, tb[NFS_ATTR_RPC_STATUS], m) {
		struct nlattr *rq_attr[NFS_ATTR_RPC_STATUS_MAX + 1];

		nla_parse_nested(rq_attr, NFS_ATTR_RPC_STATUS_MAX, rpc_attr,
				 NULL);
		if (rq_attr[NFS_ATTR_RPC_STATUS_XID])
			printf(" 0x%08x",
			       nla_get_u32(rq_attr[NFS_ATTR_RPC_STATUS_XID]));

		if (rq_attr[NFS_ATTR_RPC_STATUS_FLAGS])
			printf(" 0x%08x",
			       nla_get_u32(rq_attr[NFS_ATTR_RPC_STATUS_FLAGS]));

		if (rq_attr[NFS_ATTR_RPC_STATUS_PC_NAME])
			printf(" %s",
			       nla_get_string(rq_attr[NFS_ATTR_RPC_STATUS_PC_NAME]));

		if (rq_attr[NFS_ATTR_RPC_STATUS_VERSION])
			printf(" NFS%d",
			       nla_get_u8(rq_attr[NFS_ATTR_RPC_STATUS_VERSION]));

		if (rq_attr[NFS_ATTR_RPC_STATUS_STIME])
			printf(" %ld",
			       nla_get_u64(rq_attr[NFS_ATTR_RPC_STATUS_STIME]));

		if (rq_attr[NFS_ATTR_RPC_STATUS_SADDR4]) {
			struct in_addr addr = {
				.s_addr = nla_get_u32(rq_attr[NFS_ATTR_RPC_STATUS_SADDR4])
			};

			printf(" %s", inet_ntoa(addr));
		}

		if (rq_attr[NFS_ATTR_RPC_STATUS_SPORT])
			printf(" %hu", nla_get_u16(rq_attr[NFS_ATTR_RPC_STATUS_SPORT]));

		if (rq_attr[NFS_ATTR_RPC_STATUS_DADDR4]) {
			struct in_addr addr = {
				.s_addr = nla_get_u32(rq_attr[NFS_ATTR_RPC_STATUS_DADDR4])
			};

			printf(" %s", inet_ntoa(addr));
		}

		if (rq_attr[NFS_ATTR_RPC_STATUS_DPORT])
			printf(" %hu", nla_get_u16(rq_attr[NFS_ATTR_RPC_STATUS_DPORT]));

		if (rq_attr[NFS_ATTR_RPC_STATUS_COMPOUND]) {
			struct nlattr *comp_attr;
			int n;

			nla_for_each_nested(comp_attr,
					    rq_attr[NFS_ATTR_RPC_STATUS_COMPOUND],
					    n) {
				struct nlattr *op_attr[NFS_ATTR_RPC_STATUS_COMPOUND_MAX + 1];

				nla_parse_nested(op_attr,
						 NFS_ATTR_RPC_STATUS_COMPOUND_MAX,
						 comp_attr, NULL);
				if (!op_attr[NFS_ATTR_RPC_STATUS_COMPOUND_OP])
					continue;

				printf(" %s",
				       nla_get_string(op_attr[NFS_ATTR_RPC_STATUS_COMPOUND_OP]));
			}
		}

		printf("\n");
	}

	return NL_SKIP;
}

int main(char argc, char **argv)
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int ret = 1, id;

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;

	if (genl_connect(sock)) {
		fprintf(stderr, "Failed to connect to generic netlink\n");
		ret = -ENOLINK;
		goto out;
	}

	nl_socket_set_buffer_size(sock, BUFFER_SIZE, BUFFER_SIZE);
	setsockopt(nl_socket_get_fd(sock), SOL_NETLINK, NETLINK_EXT_ACK,
		   &ret, sizeof(ret));

	id = genl_ctrl_resolve(sock, SERVER_NAME);
	if (id < 0) {
		fprintf(stderr, "%s not found\n", SERVER_NAME);
		ret = -ENOENT;
		goto out;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		ret = -ENOMEM;
		goto out;
	}

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		ret = -ENOMEM;
		goto out;
	}

	genlmsg_put(msg, 0, 0, id, 0, 0, NFS_CMD_GET_RPC_STATUS, 0);

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
	nl_socket_free(sock);
	return ret;
}
