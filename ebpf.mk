ARCH=$(shell uname -m)
CARCH = x86

BPF_DIR := ./entries

BPF_SRC := $(wildcard $(BPF_DIR)/*.bpf.c)

TARGET_BPF = $(BPF_SRC:.c=.o)

.PHONY: all
all: $(TARGET_BPF)

$(TARGET_BPF): %.o: %.c
	clang \
		-I /usr/include/$(ARCH)-linux-gnu \
		-O2 -c -target bpf -D __TARGET_ARCH_$(CARCH) \
		-o $@ $<

.PHONY: clean
clean:
	go clean
	rm -f ./entries/*.bpf.o
	