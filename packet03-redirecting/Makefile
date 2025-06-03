
CLANG ?= clang
BPFTOOL ?= bpftool

INCLUDES := -I/usr/include/gnu
CFLAGS := -g -Wall

#$(call allow-override,CC,$(CROSS_COMPILE)cc)
#$(call allow-override,LD,$(CROSS_COMPILE)ld)

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

all: xdp_prog.bpf.o

# Build BPF code
%.bpf.o: %.bpf.c $(wildcard %.h)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -D__x86_64__		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

clean:
	rm -f xdp_prog.bpf.o xdp_prog.tmp.bpf.o

.PHONY: all clean