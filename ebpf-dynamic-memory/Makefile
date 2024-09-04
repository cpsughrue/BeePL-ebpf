TARGETS = example
BUILD_DIR = build

all: $(BUILD_DIR) $(TARGETS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGETS): $(BUILD_DIR)/example.bpf.o $(BUILD_DIR)/example

$(BUILD_DIR)/example: example.bpf.c dynamic_memory.h
	clang \
		-Wall -Wextra \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-Dnative_executable \
		-g \
		-O2 -o $@ $<

$(BUILD_DIR)/example.bpf.o: example.bpf.c dynamic_memory.h
	clang \
		-target bpf \
		-Wall -Wextra \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -o $@ -c $<

UNITY_PATH = ../unity/src
UNITTEST_SRC = unittest.c  $(UNITY_PATH)/unity.c

unittest: $(BUILD_DIR) $(UNITTEST_SRC) dynamic_memory.h
	clang \
		-Wall -Wextra \
		-Dnative_executable \
		-I$(UNITY_PATH) $(UNITTEST_SRC) \
		-o $(BUILD_DIR)/$@ && ./$(BUILD_DIR)/unittest

clean:
	rm -rf $(BUILD_DIR)

load: $(BUILD_DIR) $(BUILD_DIR)/example.bpf.o
	sudo /usr/local/sbin/bpftool prog load $(BUILD_DIR)/example.bpf.o /sys/fs/bpf/example

unload:
	sudo rm -f /sys/fs/bpf/example
