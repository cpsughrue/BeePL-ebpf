TARGETS = example
COMPILER = /home/cpsughrue/sources/llvm/llvm-project/build-runtimes/bin/clang

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: %.bpf.o %.exec

%.exec: %.bpf.c
	$(COMPILER) \
		-Wall -Wextra \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-Dnative_executable \
		-g \
	    -O2 -o $@ $<

%.bpf.o: %.bpf.c
	$(COMPILER) \
	    -target bpf \
		-Wall -Wextra \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -o $@ -c $<

clean:
	- rm *.bpf.o
	- rm *.exec
	- rm -f /sys/fs/bpf/example
