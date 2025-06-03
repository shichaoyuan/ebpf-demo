# Makefile for xdp_stats executable
CC = gcc
CFLAGS = -Wall -I.
LDFLAGS = -lbpf -lxdp

OBJS = common_params.o common_user_bpf_xdp.o xdp_stats.o

all: xdp_stats

xdp_stats: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

common_params.o: common_params.c common_params.h common_defines.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_user_bpf_xdp.o: common_user_bpf_xdp.c common_user_bpf_xdp.h common_defines.h
	$(CC) $(CFLAGS) -c -o $@ $<

xdp_stats.o: xdp_stats.c common_params.h common_user_bpf_xdp.h xdp_stats_kern_user.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f xdp_stats $(OBJS)

.PHONY: all clean
