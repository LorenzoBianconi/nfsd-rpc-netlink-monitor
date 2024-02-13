CC=gcc

nfsd-netlink:
	$(CC) -o nfsd-netlink nfsd_netlink.c -I/usr/include/libnl3/ -lnl-3 -lnl-genl-3

.PHONY: clean
clean:
	rm -f nfsd-netlink
