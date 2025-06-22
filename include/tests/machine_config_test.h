#ifndef MACHINE_CONFIG_TEST_H
#define MACHINE_CONFIG_TEST_H

#include "common_test.h"
#include "../machine_config.h"

extern ArrayMachineConfig machine_config;

/// @brief Test initialization of array machine config.
/// @param None
/// @return None
/// @details This function tests the initialization of an array of machine configurations.
/// It checks that the array is properly allocated, with an initial count of 0 and the specified capacity.
/// It also ensures that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see init_array_machine_config(), free_array_machine_config()
void test_init_array_machine_config(void);

/// @brief Test loading machine configuration from a folder.
/// @param None
/// @return None
/// @details This function tests the loading of machine configurations from a specified folder.
/// It checks that the configurations are loaded correctly, with the expected count of configurations.
/// It also verifies that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see load_machine_config(), free_array_machine_config()
void test_load_machine_config(void);

/// @brief Test loading machine configuration from a non-existent file.
/// @param None
/// @return None
/// @details This function tests the loading of machine configurations from a non-existent file.
/// It checks that the function handles the error correctly and does not crash.
/// It also verifies that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see load_machine_config(), free_array_machine_config()
void test_load_machine_config_without_file(void);

/// @brief Test freeing machine configuration.
/// @param None
/// @return None
/// @details This function tests the freeing of machine configurations.
/// It checks that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see load_machine_config(), free_array_machine_config()
void test_free_machine_config(void);

/// @brief Test freeing machine configuration with no items.
/// @param None
/// @return None
/// @details This function tests the freeing of machine configurations that have no items.
/// It checks that the memory is freed correctly after the test.
/// @note This function is part of the machine config test suite.
/// @see load_machine_config(), free_array_machine_config()
void test_free_machine_config_empty(void);

#endif // MACHINE_CONFIG_TEST_H