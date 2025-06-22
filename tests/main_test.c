#include "../include/tests/common_test.h"
#include "../include/tests/stack_test.h"
#include "../include/tests/machine_config_test.h"

void setUp(void) {
    // Code exécuté avant chaque test
    machine_config = (ArrayMachineConfig){0};
}

void tearDown(void) {
    // Code exécuté après chaque test
    //system("leaks test_opcuaserver"); // Ajouter cette ligne
    free_array_machine_config(&machine_config);
    
    // Force cleanup of any remaining JSON objects
    while (json_object_put(NULL) > 0) {
        // Keep releasing until all references are cleared
    }
}

int main(void) {
    UNITY_BEGIN();
    
    // Machine config tests
    RUN_TEST(test_init_array_machine_config);
    RUN_TEST(test_load_machine_config_without_file);  
    RUN_TEST(test_load_machine_config);
    RUN_TEST(test_free_machine_config);
    RUN_TEST(test_free_machine_config_empty);
  

    //stack tests
    RUN_TEST(test_stack_init);
    RUN_TEST(test_stack_push);
    RUN_TEST(test_stack_pop);
    RUN_TEST(test_stack_pop_empty);
    RUN_TEST(test_stack_peek);
    RUN_TEST(test_stack_peek_empty);
    RUN_TEST(test_stack_init_with_zero_capacity);
    RUN_TEST(test_stack_push_over_capacity);

    return UNITY_END();
}