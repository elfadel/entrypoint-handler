KDIR=/lib/modules/5.8.0#$(shell uname -r)
INCLUDES += -I$(KDIR)/build/arch/x86/include/generated/uapi
INCLUDES += -I$(KDIR)/build/arch/x86/include/generated
INCLUDES += -I$(KDIR)/build/arch/x86/include/
INCLUDES += -I$(KDIR)/build/arch/x86/include/uapi
INCLUDES += -I$(KDIR)/build/include
INCLUDES += -I$(KDIR)/build/include/uapi
INCLUDES += -I$(KDIR)/build/include/generated/uapi
INCLUDES += -include $(KDIR)/build/include/linux/kconfig.h

BPF_DIR := ./entries

BPF_SRC := $(wildcard $(BPF_DIR)/*.bpf.c)

TARGET_BPF = $(BPF_SRC:.c=.o)

LLC=llc
CLANG=clang

.PHONY: all
all: $(TARGET_BPF)

$(TARGET_BPF): %.o: %.c
	$(CLANG) -S $(INCLUDES) \
		-I headers \
		-D__TARGET_ARCH_x86 -D__KERNEL__ \
		-Wno-address-of-packed-member \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-tautological-compare \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

.PHONY: clean
clean:
	rm -f ./entries/*.ll
	rm -f ./entries/*.bpf.o