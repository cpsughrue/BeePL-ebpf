TARGETS = hello

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: %.bpf.o %.exec

%.exec: %.bpf.c
	clang \
		-Wall -Wextra \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -o $@ $<

%.bpf.o: %.bpf.c
	clang \
	    -target bpf \
		-Wall -Wextra \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-DeBPF \
		-g \
	    -O2 -o $@ -c $<

clean: 
	- rm *.bpf.o
	- rm *.exec
	- rm -f /sys/fs/bpf/hello
