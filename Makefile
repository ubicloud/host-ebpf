# The object is a build artifact embedded into the binary, compiled with the
# pinned clang so what ships is always derived from the source alongside it.
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
	go test ./...
	sudo ./test/run_tests.sh

clean:
	rm -f host-ebpf $(OBJ)

.PHONY: all test clean
