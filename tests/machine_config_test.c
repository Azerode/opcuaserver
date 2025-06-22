#include "../include/tests/machine_config_test.h"

ArrayMachineConfig machine_config = {0};

/// @brief Test initialization of array machine config.
/// @param None
/// @return None
/// @details This function tests the initialization of an array of machine configurations.
/// It checks that the array is properly allocated, with an initial count of 0 and the specified capacity.
/// It also ensures that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see init_array_machine_config(), free_array_machine_config()
void test_init_array_machine_config(void){
    init_array_machine_config(&machine_config, 8);

    TEST_ASSERT_NOT_NULL(machine_config.configs);
    TEST_ASSERT_EQUAL_INT(0, machine_config.count);
    TEST_ASSERT_EQUAL_INT(8, machine_config.capacity);
}

/// @brief Test loading machine configuration from a folder.
/// @param None
/// @return None
/// @details This function tests the loading of machine configurations from a specified folder.
/// It checks that the configurations are loaded correctly, with the expected count of configurations.
/// It also verifies that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see load_machine_config(), free_array_machine_config()
void test_load_machine_config(void){

    load_machine_config("tests/fixtures/filled", &machine_config);

    TEST_ASSERT_NOT_NULL(machine_config.configs);
    TEST_ASSERT_EQUAL_INT(8, machine_config.capacity);
    TEST_ASSERT_EQUAL_INT(3, machine_config.count);
}

/// @brief Test loading machine configuration from a non-existent file.
/// @param None
/// @return None
/// @details This function tests the loading of machine configurations from a non-existent file.
/// It checks that the function handles the error correctly and does not crash.
/// It also verifies that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see load_machine_config(), free_array_machine_config()
void test_load_machine_config_without_file(void){

    load_machine_config("tests/fixtures/empty", &machine_config);

    TEST_ASSERT_NOT_NULL(machine_config.configs);
    TEST_ASSERT_EQUAL_INT(8, machine_config.capacity);
    TEST_ASSERT_EQUAL_INT(0, machine_config.count);
}

/// @brief Test freeing machine configuration.
/// @param None
/// @return None
/// @details This function tests the freeing of machine configurations.
/// It checks that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see load_machine_config(), free_array_machine_config()
void test_free_machine_config(void){

    load_machine_config("tests/fixtures/filled", &machine_config);
    free_array_machine_config(&machine_config);
    json_object_put(NULL);

    TEST_ASSERT_EQUAL_INT(0, machine_config.count);
    TEST_ASSERT_EQUAL_INT(0, machine_config.capacity);
    TEST_ASSERT_NULL(machine_config.configs);
}

/// @brief Test freeing machine configuration with no items.
/// @param None
/// @return None
/// @details This function tests the freeing of machine configurations that have no items.
/// It checks that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see load_machine_config(), free_array_machine_config()
void test_free_machine_config_empty(void){

    load_machine_config("tests/fixtures/empty", &machine_config);
    free_array_machine_config(&machine_config);
    json_object_put(NULL);

    TEST_ASSERT_EQUAL_INT(0, machine_config.count);
    TEST_ASSERT_EQUAL_INT(0, machine_config.capacity);
    TEST_ASSERT_NULL(machine_config.configs);
}
