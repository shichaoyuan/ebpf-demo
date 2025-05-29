
CLANG ?= clang
BPFTOOL ?= bpftool

INCLUDES := -I.
CFLAGS := -g -Wall

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath .)/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

vmlinux.h:
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Build BPF code
%.bpf.o: %.bpf.c $(wildcard %.h) | vmlinux.h
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

%.o: %.c $(wildcard %.h)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

xdp_load_and_stats: xdp_load_and_stats.o common_params.o common_user_bpf_xdp.o
	$(call msg, xdp_load_and_stats, $@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lxdp -lbpf -lz -o $@