#ifndef MACHINE_CONFIG_H
#define MACHINE_CONFIG_H

#include "common.h"
#include "stack.h"
#include <json.h>

typedef struct {
    char* name;
    char* nodeId;
    char* type;
} Item;

typedef struct {
    size_t count;
    size_t capacity;
    Item* items;
} ArrayItem;

typedef struct {
    char* name;
    ArrayItem items;
} Group;

typedef struct {
    size_t count;
    size_t capacity;
    Group* groups;
} ArrayGroup;

typedef struct {
    char* name;
    char* url;
    char* namespace;
    ArrayGroup groups;
} MachineConfig;

typedef struct {
    size_t count;
    size_t capacity;
    MachineConfig* configs;
} ArrayMachineConfig;


/// @brief Initialize an array of machine configurations
/// @param array_machine_config Pointer to the ArrayMachineConfig structure to initialize
/// @param initial_capacity Initial capacity for the array
/// @note This function will allocate memory for the configs array and set the count to 0.
void init_array_machine_config(ArrayMachineConfig* array_machine_config, size_t initial_capacity);

/// @brief Load machine configuration from a folder
/// @param folderPath Path to the configuration folder
/// @return Pointer to the loaded MachineConfig structure, or NULL on failure
/// @note The caller is responsible for freeing the returned structure using FreeMachineConfig.
void load_machine_config(const char* folderPath, ArrayMachineConfig* listMachineConfig);

/// @brief Free the memory allocated for an array of items
/// @param array Pointer to the ArrayItem structure to free
/// @note This function will free all memory associated with the ArrayItem, including its items.
void free_array_item(ArrayItem* array);

/// @brief Free the memory allocated for an array of groups
/// @param array Pointer to the ArrayGroup structure to free
/// @note This function will free all memory associated with the ArrayGroup, including its groups.
void free_array_group(ArrayGroup* array);

/// @brief Free the memory allocated for an array of machine configurations
/// @param array Pointer to the ArrayMachineConfig structure to free
/// @note This function will free all memory associated with the ArrayMachineConfig, including its configs.
void free_array_machine_config(ArrayMachineConfig* array);

/// @brief Free the memory allocated for an array of groups
/// @param array Pointer to the ArrayGroup structure to free
/// @note This function will free all memory associated with the ArrayGroup, including its groups.
void free_array_group(ArrayGroup* array);

/// @brief Free the memory allocated for an array of items
/// @param array Pointer to the ArrayItem structure to free
/// @note This function will free all memory associated with the ArrayItem, including its items.
void free_array_item(ArrayItem* array);

#endif // MACHINE_CONFIG_H