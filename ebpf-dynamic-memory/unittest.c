#include <string.h>
#include "unity.h"

// define POOL_SIZE and MAX_ALLOCS above "dynamic_memory.h" to reduce pool size
#define POOL_SIZE 256
#define MAX_ALLOCS 8

#include "dynamic_memory.h"

const uint8_t zero_memory_pool[POOL_SIZE] = {0};
const struct alloc_info zero_alloc_metadata[MAX_ALLOCS] = {0};

void print(uint8_t *memory) {
    for (int i = 0; i < POOL_SIZE; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            printf("%c", (memory[i] & (1 << bit)) ? '1' : '0');
        }
        printf(" ");
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
}

// Confrim values of POOL_SIZE and MAX_ALLOC are not being overwritten
void test_constants(void) {
    TEST_ASSERT_EQUAL_INT16(POOL_SIZE, 256);
    TEST_ASSERT_EQUAL_INT16(MAX_ALLOCS, 8);
}

void setUp(void) {
    memset(memory_pool, 0, sizeof(memory_pool[0]) * POOL_SIZE);
    memset(alloc_metadata, 0, sizeof(alloc_metadata[0]) * MAX_ALLOCS);
}

// UnityDefaultTestRun requires tearDown to be defined
void tearDown(void) {}

void test_size_zero_static_malloc(void) {
    void *ptr = static_malloc(0);
    TEST_ASSERT_EQUAL_PTR(NULL, ptr);
    TEST_ASSERT_EQUAL_INT8_ARRAY(zero_memory_pool, memory_pool, POOL_SIZE);
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(zero_alloc_metadata, alloc_metadata, sizeof(struct alloc_info), MAX_ALLOCS);
}

void test_size_to_large_static_malloc(void) {
    void *ptr = static_malloc(POOL_SIZE + 1);
    TEST_ASSERT_EQUAL_PTR(NULL, ptr);
    TEST_ASSERT_EQUAL_INT8_ARRAY(zero_memory_pool, memory_pool, POOL_SIZE);
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(zero_alloc_metadata, alloc_metadata, sizeof(struct alloc_info), MAX_ALLOCS);
}

void test_size_pool_max_static_malloc(void) {
    void *ptr = static_malloc(POOL_SIZE);
    TEST_ASSERT_EQUAL_PTR(memory_pool, ptr);
    TEST_ASSERT_EQUAL_INT8_ARRAY(zero_memory_pool, memory_pool, POOL_SIZE);
    
    struct alloc_info block = {
        .in_use = true,
        .start = 0,
        .size = POOL_SIZE
    };
    
    TEST_ASSERT_EQUAL_MEMORY(&block, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[1], &alloc_metadata[1], sizeof(struct alloc_info), MAX_ALLOCS - 1);
}

void test_eight_byte_alignment_static_malloc_1(void) {
    void *ptr = static_malloc(4);
    TEST_ASSERT_EQUAL_PTR(memory_pool, ptr);
    TEST_ASSERT_EQUAL_INT8_ARRAY(zero_memory_pool, memory_pool, POOL_SIZE);
    
    struct alloc_info block = {
        .in_use = true,
        .start = 0,
        .size = 8
    };
    
    TEST_ASSERT_EQUAL_MEMORY(&block, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[1], &alloc_metadata[1], sizeof(struct alloc_info), MAX_ALLOCS - 1);
}

void test_eight_byte_alignment_static_malloc_2(void) {
    void *ptr = static_malloc(12);
    TEST_ASSERT_EQUAL_PTR(memory_pool, ptr);
    TEST_ASSERT_EQUAL_INT8_ARRAY(zero_memory_pool, memory_pool, POOL_SIZE);
    
    struct alloc_info block = {
        .in_use = true,
        .start = 0,
        .size = 16
    };
    
    TEST_ASSERT_EQUAL_MEMORY(&block, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[1], &alloc_metadata[1], sizeof(struct alloc_info), MAX_ALLOCS - 1);
}

void test_data_insertion_static_malloc(void) {
    uint8_t *ptr = (uint8_t*)static_malloc(8);
    TEST_ASSERT_EQUAL_PTR(memory_pool, ptr);

    *ptr = 255;
    TEST_ASSERT_EQUAL_INT8(255, memory_pool[0]);
    TEST_ASSERT_EQUAL_INT8_ARRAY(&zero_memory_pool[1], &memory_pool[1], POOL_SIZE - 1);

    struct alloc_info block = {
        .in_use = true,
        .start = 0,
        .size = 8
    };
    
    TEST_ASSERT_EQUAL_MEMORY(&block, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[1], &alloc_metadata[1], sizeof(struct alloc_info), MAX_ALLOCS - 1);
}

void test_multiple_static_malloc(void) {
    void *ptr1 = static_malloc(12);
    void *ptr2 = static_malloc(128);
    void *ptr3 = static_malloc(3);

    TEST_ASSERT_EQUAL_PTR(&memory_pool[0], ptr1);
    TEST_ASSERT_EQUAL_PTR(&memory_pool[16], ptr2);
    TEST_ASSERT_EQUAL_PTR(&memory_pool[144], ptr3);
    
    struct alloc_info block1 = {
        .in_use = true,
        .start = 0,
        .size = 16
    };
    struct alloc_info block2 = {
        .in_use = true,
        .start = 16,
        .size = 128
    };
    struct alloc_info block3 = {
        .in_use = true,
        .start = 144,
        .size = 8
    };
    
    TEST_ASSERT_EQUAL_MEMORY(&block1, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY(&block2, &alloc_metadata[1], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY(&block3, &alloc_metadata[2], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[3], &alloc_metadata[3], sizeof(struct alloc_info), MAX_ALLOCS - 3);
}

void test_block_reuse_static_free(void) {
    uint8_t *ptr1 = (uint8_t*)static_malloc(8);
    *ptr1 = 255;

    TEST_ASSERT_EQUAL_INT8(255, memory_pool[0]);
    TEST_ASSERT_EQUAL_INT8_ARRAY(&zero_memory_pool[1], &memory_pool[1], POOL_SIZE - 1);

    struct alloc_info block = {
        .in_use = true,
        .start = 0,
        .size = 8
    };
    
    TEST_ASSERT_EQUAL_MEMORY(&block, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[1], &alloc_metadata[1], sizeof(struct alloc_info), MAX_ALLOCS - 1);

    static_free(ptr1);
    block.in_use = false; 
    TEST_ASSERT_EQUAL_MEMORY(&block, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[1], &alloc_metadata[1], sizeof(struct alloc_info), MAX_ALLOCS - 1);
    
    // The block created for the first static_malloc should be resused for the second
    uint8_t *ptr2 = (uint8_t*)static_malloc(8);
    block.in_use = true; 
    TEST_ASSERT_EQUAL_MEMORY(&block, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[1], &alloc_metadata[1], sizeof(struct alloc_info), MAX_ALLOCS - 1);
}

// NOTE: This is behavior that should probably change. There is no reason the 
// allocation of 32 cannot resize the first block
void test_block_too_large_static_free(void) {
    uint8_t *ptr1 = (uint8_t*)static_malloc(8);
    *ptr1 = 255;

    TEST_ASSERT_EQUAL_INT8(255, memory_pool[0]);
    TEST_ASSERT_EQUAL_INT8_ARRAY(&zero_memory_pool[1], &memory_pool[1], POOL_SIZE - 1);

    struct alloc_info block1 = {
        .in_use = true,
        .start = 0,
        .size = 8
    };
    
    TEST_ASSERT_EQUAL_MEMORY(&block1, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[1], &alloc_metadata[1], sizeof(struct alloc_info), MAX_ALLOCS - 1);

    static_free(ptr1);
    block1.in_use = false; 
    TEST_ASSERT_EQUAL_MEMORY(&block1, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[1], &alloc_metadata[1], sizeof(struct alloc_info), MAX_ALLOCS - 1);
    
    uint8_t *ptr2 = (uint8_t*)static_malloc(32);
    
    struct alloc_info block2 = {
        .in_use = true,
        .start = 8,
        .size = 32
    };
    
    TEST_ASSERT_EQUAL_MEMORY(&block1, &alloc_metadata[0], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY(&block2, &alloc_metadata[1], sizeof(struct alloc_info));
    TEST_ASSERT_EQUAL_MEMORY_ARRAY(&zero_alloc_metadata[2], &alloc_metadata[2], sizeof(struct alloc_info), MAX_ALLOCS - 2);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_constants);
    
    // tests that only call static_malloc
    RUN_TEST(test_size_zero_static_malloc);
    RUN_TEST(test_size_to_large_static_malloc);
    RUN_TEST(test_size_pool_max_static_malloc);
    RUN_TEST(test_eight_byte_alignment_static_malloc_1);
    RUN_TEST(test_eight_byte_alignment_static_malloc_2);
    RUN_TEST(test_data_insertion_static_malloc);
    RUN_TEST(test_multiple_static_malloc);

    // tests focused on static_free
    RUN_TEST(test_block_reuse_static_free);
    RUN_TEST(test_block_too_large_static_free);

    return UNITY_END();
}


