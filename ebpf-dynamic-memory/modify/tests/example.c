#include <stdlib.h>
#define SIZE 64

void test(void* data){
    free(data);
};

int main(){

    // Should be replaced
    int *ptr1 = (int*)malloc(SIZE * sizeof(int));
    free(ptr1);
    
    void *ptr2 = malloc(SIZE * sizeof(int)); free(ptr2);
    
    void*ptr3=malloc(SIZE*sizeof(int));free(ptr3);

    test(malloc(SIZE*sizeof(int)));

    // Should not be replaced
    // malloc
    // free
    // mallocX
    // freeX
    // Xmalloc
    // Xfree
    // Xmalloc(
    // Xfree(

    return 0;
}
