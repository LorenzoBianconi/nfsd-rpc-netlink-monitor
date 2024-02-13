CC=gcc

nfsdctl:
	$(CC) -o nfsdctl nfsdctl.c -I/usr/include/libnl3/ -lnl-3 -lnl-genl-3

.PHONY: clean
clean:
	rm -f nfsdctl
