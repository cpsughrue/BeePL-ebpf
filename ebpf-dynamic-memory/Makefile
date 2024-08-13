TARGETS = example

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: %.bpf.o %.exe

%.exe: %.bpf.c
	clang \
		-Wall -Wextra \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-Dnative_executable \
		-g \
	    -O2 -o $@ $<

%.bpf.o: %.bpf.c
	clang \
	    -target bpf \
		-Wall -Wextra \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -o $@ -c $<

UNITY_PATH = ../unity/src
UNITTEST_SRC = unittest.c  $(UNITY_PATH)/unity.c

unittest: $(UNITTEST_SRC) dynamic_memory.h
	clang $(UNITTEST_SRC) -I$(UNITY_PATH) -Dnative_executable -o $@ && ./unittest

clean:
	- rm -f *.bpf.o
	- rm -f *.exe
	- rm -f unittest

unload:
	- rm -f /sys/fs/bpf/example
