TARGET := entrypoint

BPF_DIR := ./entries

GO_SRC := *.go
BPF_SRC := $(wildcard $(BPF_DIR)/*.bpf.c)

TARGET_BPF = $(BPF_SRC:.c=.o)

LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := ./lib/libbpf.a

.PHONY: all
all: $(TARGET) #$(TARGET_BPF)

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET)

.PHONY: clean
clean:
	go clean
	rm -f ./entries/*.bpf.o
	