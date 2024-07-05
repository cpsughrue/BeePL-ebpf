/* Type your code here, or load an example. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define POOL_SIZE 1024

struct block {
    size_t size; // size represents amount of space for user data
    bool free;
    struct block *next;
};

static uint8_t pool[POOL_SIZE];
static struct block *list = (struct block *)pool;
static bool is_initialized = false;
static uint32_t num_blocks = 1;

void initialize_pool() {
    list->size = POOL_SIZE - sizeof(struct block);
    list->free = true;
    list->next = NULL;
    is_initialized = true;
}

void *static_malloc(size_t size){
    if(is_initialized == false) initialize_pool();

    // must keep data 8 bytes alighned 
    if (size % 8 != 0)
        size = ((size / 8) + 1) * 8;

    if(size <= 0 || size > POOL_SIZE)
        return NULL;

    uint32_t curr_position = 0;

    for(int i = 0; i < num_blocks; i++) {
        
        if(curr_position + sizeof(struct block) > POOL_SIZE)
            return NULL;
        struct block *curr = (struct block *)(pool + curr_position);
        
        // find a block that is free and large enough to hold data
        if(curr->free == true && curr->size >= size){
            // block is either the perfect size or there is not at enogh space to split into two
            //
            // to split a block into two, curr->size must be larger then the amount of space 
            // requested by the user plus the size of a struct block
            if(curr->size <= size + sizeof(struct block)) {
                curr->free = false;
            }
            // block is large enogh to split into two
            else {
                if(curr_position + (2 * sizeof(struct block)) + size > POOL_SIZE)
                    return NULL;
                struct block *new_block = (struct block *)(pool + curr_position + sizeof(struct block) + size);

                new_block->size = curr->size - size - sizeof(struct block);
                new_block->free = true;
                new_block->next = curr->next;

                // set values of curr
                curr->size = size;
                curr->free = false;
                curr->next = new_block;
                num_blocks++;
            }
            
            if(curr_position + sizeof(struct block) + size > POOL_SIZE)
                return NULL;
            return &pool[curr_position + sizeof(struct block)];
        }
        curr_position += sizeof(struct block) + curr->size;
    }
    return NULL;
}

int counter = 0;

typedef struct vec2 {
    int x;
    int y;
} vec2_t;

void dump_pool() {
    struct block *curr = list;
    printf("dump pool: %p\n", curr);
    printf("==============\n");
    for(int i = 0; i < num_blocks; i++) {
        printf("size: %zu\n", curr->size);
        printf("free: %d\n", curr->free);
        printf("next: %p\n", curr->next);
        if(!(i == num_blocks - 1))
            printf("==============\n");
        curr = curr->next;
    }
    printf("\n\n");
}

// int main() {
//     vec2_t *data1 = (vec2_t *)static_malloc(sizeof(vec2_t));
//     dump_pool();
    
//     vec2_t *data2 = (vec2_t *)static_malloc(100);
//     dump_pool();

//     vec2_t *data3 = (vec2_t *)static_malloc(820);
//     dump_pool();
// }
