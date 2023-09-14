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

#include "nfsd.h"

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

static int recv_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NFSD_ATTR_RPC_STATUS_MAX + 1];

	nla_parse(tb, NFSD_ATTR_RPC_STATUS_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NFSD_ATTR_RPC_STATUS_XID])
		printf(" 0x%08x", nla_get_u32(tb[NFSD_ATTR_RPC_STATUS_XID]));

	if (tb[NFSD_ATTR_RPC_STATUS_FLAGS])
		printf(" 0x%08x", nla_get_u32(tb[NFSD_ATTR_RPC_STATUS_FLAGS]));

	if (tb[NFSD_ATTR_RPC_STATUS_PROG])
		printf(" %d", nla_get_u32(tb[NFSD_ATTR_RPC_STATUS_PROG]));

	if (tb[NFSD_ATTR_RPC_STATUS_VERSION])
		printf(" NFS%d", nla_get_u8(tb[NFSD_ATTR_RPC_STATUS_VERSION]));

	if (tb[NFSD_ATTR_RPC_STATUS_PROC])
		printf(" %d", nla_get_u32(tb[NFSD_ATTR_RPC_STATUS_PROC]));

	if (tb[NFSD_ATTR_RPC_STATUS_SERVICE_TIME])
		printf(" %ld",
		       nla_get_u64(tb[NFSD_ATTR_RPC_STATUS_SERVICE_TIME]));

	if (tb[NFSD_ATTR_RPC_STATUS_SADDR4]) {
		struct in_addr addr = {
			.s_addr = nla_get_u32(tb[NFSD_ATTR_RPC_STATUS_SADDR4])
		};

		printf(" %s", inet_ntoa(addr));
	}

	if (tb[NFSD_ATTR_RPC_STATUS_SPORT])
		printf(" %hu", nla_get_u16(tb[NFSD_ATTR_RPC_STATUS_SPORT]));

	if (tb[NFSD_ATTR_RPC_STATUS_DADDR4]) {
		struct in_addr addr = {
			.s_addr = nla_get_u32(tb[NFSD_ATTR_RPC_STATUS_DADDR4])
		};

		printf(" %s", inet_ntoa(addr));
	}

	if (tb[NFSD_ATTR_RPC_STATUS_DPORT])
		printf(" %hu", nla_get_u16(tb[NFSD_ATTR_RPC_STATUS_DPORT]));

	if (tb[NFSD_ATTR_RPC_STATUS_COMPOUND_OP]) {
		struct nlattr *op_attr[NFSD_ATTR_COMPOUND_MAX + 1];
		struct nlattr *attr;
		int m;

		nla_for_each_nested(attr,
				    tb[NFSD_ATTR_RPC_STATUS_COMPOUND_OP], m) {
			unsigned int op;

			nla_parse_nested(op_attr, NFSD_ATTR_COMPOUND_MAX,
					 attr, NULL);
			if (!op_attr[NFSD_ATTR_COMPOUND_OP])
				continue;

			op = nla_get_u32(op_attr[NFSD_ATTR_COMPOUND_OP]);
			if (op < NFSD4_OPS_MAX_LEN)
				printf(" %s", nfsd4_ops[op]);
		}
	}
	printf("\n");

	return NL_SKIP;
}

#define BUFFER_SIZE	8192
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

	id = genl_ctrl_resolve(sock, NFSD_FAMILY_NAME);
	if (id < 0) {
		fprintf(stderr, "%s not found\n", NFSD_FAMILY_NAME);
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

	genlmsg_put(msg, 0, 0, id, 0, NLM_F_DUMP, NFSD_CMD_RPC_STATUS_GET, 0);

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
