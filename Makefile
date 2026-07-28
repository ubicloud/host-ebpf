# The committed object must be byte-reproducible: CI recompiles with the
# pinned clang and fails if the result differs.
CLANG ?= clang-18
OBJ := internal/ndpproxy/bpf/ndp_proxy.bpf.o

CFLAGS := -O2 -g -Wall -Werror -target bpf \
	-fdebug-prefix-map=$(CURDIR)=. -ffile-prefix-map=$(CURDIR)=. \
	-I/usr/include/$(shell uname -m)-linux-gnu

all: host-ebpf

$(OBJ): internal/ndpproxy/bpf/ndp_proxy.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

host-ebpf: $(OBJ) $(wildcard *.go internal/ndpproxy/*.go)
	CGO_ENABLED=0 go build -trimpath -o host-ebpf .

test: host-ebpf
	go vet ./...
	sudo ./test/run_tests.sh

clean:
	rm -f host-ebpf $(OBJ)

.PHONY: all test clean
