#include "unity.h"
#include "dynamic_memory.h"

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

void test_function_1(void) {
    //test stuff
}

void test_function_2(void) {
    TEST_ASSERT_EQUAL_INT(3, 5);
}

// not needed when using generate_test_runner.rb
int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_function_1);
    RUN_TEST(test_function_2);
    return UNITY_END();
}
