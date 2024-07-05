#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>

void *static_malloc(size_t size);
void dump_pool();

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  
  int data[2];
  void *return_val = data;
  
  while(return_val != NULL)
    return_val = static_malloc(rand() % 256);

  //dump_pool();

  return 0;  // Values other than 0 and -1 are reserved for future use.
}