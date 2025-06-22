#include "../include/machine_config.h"
#include <dirent.h>
#include <limits.h>



// Private functions (static)
// In the case where we cannot manage functions in order in the file
static void _init_array_item(ArrayItem* array_item, size_t initial_capacity);
static void _init_array_group(ArrayGroup* array_group, size_t initial_capacity);
static void _check_size_machine_config(ArrayMachineConfig* array_machine_config);

static void _parse_items(struct json_object* array_item_json, ArrayItem* array_item);
static void _parse_groups(struct json_object* array_group_json, ArrayGroup* array_group);
static void _parse_machine_config(struct json_object* machine_config_json, ArrayMachineConfig* array_machine_config);

/// @brief Check and resize the array of machine configurations if necessary
/// @param array_machine_config Pointer to the ArrayMachineConfig structure to check
/// @note This function will double the capacity of the array if the current count reaches the capacity.
static void _check_size_machine_config(ArrayMachineConfig* array_machine_config) {

    if (!array_machine_config) return;

    if (array_machine_config->count >= array_machine_config->capacity) {
        size_t new_capacity = array_machine_config->capacity * 2;
        array_machine_config->configs = (MachineConfig*)realloc(array_machine_config->configs, sizeof(MachineConfig) * new_capacity);
        if (!array_machine_config->configs) {
            fprintf(stderr, "Failed to reallocate memory for MachineConfig\n");
            exit(EXIT_FAILURE);
        }
        array_machine_config->capacity = new_capacity;
    }
}

/// @brief Initialize an array of groups
/// @param array_group Pointer to the ArrayGroup structure to initialize
/// @param initial_capacity Initial capacity for the array
/// @note This function will allocate memory for the groups array and set the count to 0.
static void _init_array_group(ArrayGroup* array_group, size_t initial_capacity) {

    if (!array_group) {
        array_group = (ArrayGroup*)malloc(sizeof(ArrayGroup));
        if (!array_group) {
            fprintf(stderr, "Failed to allocate memory for ArrayGroup\n");
            exit(EXIT_FAILURE);;
        }
    }

    array_group->count = 0;
    array_group->capacity = initial_capacity;
    array_group->groups = (Group*)malloc(sizeof(Group) * initial_capacity);
    if (!array_group->groups) {
        fprintf(stderr, "Failed to allocate memory for groups in ArrayGroup\n");
        free(array_group);
        exit(EXIT_FAILURE);
    }
}

/// @brief Initialize an array of items
/// @param array_item Pointer to the ArrayItem structure to initialize
/// @param initial_capacity Initial capacity for the array
/// @note This function will allocate memory for the items array and set the count to 0.
static void _init_array_item(ArrayItem* array_item, size_t initial_capacity){

    if (!array_item){
        array_item = (ArrayItem*)malloc(sizeof(ArrayItem));
        if (!array_item) {
            fprintf(stderr, "Failed to allocate memory for ArrayItem\n");
            exit(EXIT_FAILURE);
        }
    }

    array_item->count = 0;
    array_item->capacity = initial_capacity;
    array_item->items = (Item*)malloc(sizeof(Item) * initial_capacity);
    if (!array_item->items) {
        fprintf(stderr, "Failed to allocate memory for items in ArrayItem\n");
        free(array_item);
        exit(EXIT_FAILURE);
    }
}

/// @brief Free the memory allocated for an array of items
/// @param array Pointer to the ArrayItem structure to free
/// @note This function will free all memory associated with the ArrayItem, including its items.
void free_array_item(ArrayItem* array){
    if(array == NULL) return;

    if (array->items != NULL){
        for(size_t i = 0; i < array->count; i++){

            if (array->items[i].name != NULL){
                free(array->items[i].name);
            }
            if (array->items[i].nodeId != NULL){
                free(array->items[i].nodeId);
            }
            if (array->items[i].type != NULL){
                free(array->items[i].type);
            }
        }

        free(array->items);
    }

    array->count = 0;
    array->capacity = 0;
    array->items = NULL;
}

/// @brief Free the memory allocated for an array of groups
/// @param array Pointer to the ArrayGroup structure to free
/// @note This function will free all memory associated with the ArrayGroup, including its groups.
void free_array_group(ArrayGroup* array){
    if(array == NULL) return;

    if(array-> groups != NULL){
        for(size_t i = 0; i < array->count; i++){

            if(array->groups[i].name != NULL){
                free(array->groups[i].name);
            }

            free_array_item(&array->groups[i].items);
        }

        free(array->groups);
    }

    array->count = 0;
    array->capacity = 0;
    array->groups = NULL;
}

/// @brief Free the memory allocated for an array of machine configurations
/// @param array Pointer to the ArrayMachineConfig structure to free
/// @note This function will free all memory associated with the ArrayMachineConfig, including its configs.
void free_array_machine_config(ArrayMachineConfig* array){
    
    if(!array) return;

    if(array->configs != NULL){
        for (size_t i = 0; i < array->count; i++) {

            if (array->configs[i].name != NULL) {
                free(array->configs[i].name);
            }

            if (array->configs[i].url != NULL) {
                free(array->configs[i].url);
            }

            if (array->configs[i].namespace != NULL) {
                free(array->configs[i].namespace);
            }

            // Free groups
            free_array_group(&(array->configs[i].groups));
        }

        free(array->configs);
    }
 
    array->count = 0;
    array->capacity = 0;
    array->configs = NULL;
}


/// @brief Parse items from JSON
/// @param array_item_json The JSON array containing item information
/// @param array_item The array to store parsed item information
/// @note This function will resize the array_item if necessary.
static void _parse_items(struct json_object* array_item_json, ArrayItem* array_item){

    int array_length = 0;
    struct json_object* item_obj;
    struct json_object* temp;

    if (!array_item_json) return;

    array_length = json_object_array_length(array_item_json);

    _init_array_item(array_item, array_length);

    if (!array_item->items) {
        fprintf(stderr, "Failed to initialize array_item\n");
        return;
    }

    for(int i = 0; i < array_length; i++){
        item_obj = json_object_array_get_idx(array_item_json, i);
        
        if (json_object_object_get_ex(item_obj, "name", &temp)){
            array_item->items[i].name = strdup(json_object_get_string(temp));
        }
        if (json_object_object_get_ex(item_obj, "nodeId", &temp)){
            array_item->items[i].nodeId = strdup(json_object_get_string(temp));
        }
        if (json_object_object_get_ex(item_obj, "type", &temp)){
            array_item->items[i].type = strdup(json_object_get_string(temp));
        }

        array_item->count++;
    }
}


/// @brief Parse groups from JSON
/// @param array_group_json The JSON array containing group information
/// @param array_group The array to store parsed group information
/// @note This function will resize the array_group if necessary.
static void _parse_groups(struct json_object* array_group_json, ArrayGroup* array_group){
    
    int array_length = 0;
    struct json_object* temp;
    struct json_object* group_obj;

    if (!array_group_json) return;

    array_length = json_object_array_length(array_group_json);

    _init_array_group(array_group, array_length);
    
    if (!array_group->groups) {
        fprintf(stderr, "Failed to initialize array_group\n");
        return;
    }

    for(int i = 0; i < array_length; i++){
        group_obj = json_object_array_get_idx(array_group_json, i);

        if (json_object_object_get_ex(group_obj, "name", &temp)){
            array_group->groups[i].name = strdup(json_object_get_string(temp));
        }
        if (json_object_object_get_ex(group_obj, "items", &temp)){
            _parse_items(temp, &array_group->groups[i].items);
        }
        array_group->count++;
    }
}

/// @brief Parse machine configuration from JSON
/// @param machine_config_json The JSON object containing machine configuration
/// @param array_machine_config The array to store parsed machine configurations
/// @note This function will resize the array_machine_config if necessary.
static void _parse_machine_config(struct json_object* machine_config_json, ArrayMachineConfig* array_machine_config){
    
    struct json_object* temp;
    
    if (!machine_config_json) return;

    _check_size_machine_config(array_machine_config);

    if(json_object_object_get_ex(machine_config_json,"name",&temp)){
        array_machine_config->configs[array_machine_config->count].name = strdup(json_object_get_string(temp));
    }

    if(json_object_object_get_ex(machine_config_json,"url",&temp)){
        array_machine_config->configs[array_machine_config->count].url = strdup(json_object_get_string(temp));
    }

    if (json_object_object_get_ex(machine_config_json,"namespace",&temp)){
        array_machine_config->configs[array_machine_config->count].namespace = strdup(json_object_get_string(temp));
    }

    if (json_object_object_get_ex(machine_config_json,"groups",&temp)){
        _parse_groups(temp, &array_machine_config->configs[array_machine_config->count].groups);
    }

    array_machine_config->count++;
}

/// @brief Initialize an array of machine configurations
/// @param array_machine_config Pointer to the ArrayMachineConfig structure to initialize
/// @param initial_capacity Initial capacity for the array
/// @note This function will allocate memory for the configs array and set the count to 0.
void init_array_machine_config(ArrayMachineConfig* array_machine_config, size_t initial_capacity){
    
    array_machine_config->count = 0;
    array_machine_config->capacity = initial_capacity;
    array_machine_config->configs = (MachineConfig *) malloc(sizeof(MachineConfig) * array_machine_config->capacity);
    memset(array_machine_config->configs, 0, sizeof(MachineConfig) * array_machine_config->capacity);
    
    if (!array_machine_config->configs) {
        fprintf(stderr, "Failed to allocate memory for configs\n");
        array_machine_config->capacity = 0;
        array_machine_config->configs = NULL;
        return;
    }
}

/// @brief Load machine configuration from a folder
/// @param folderPath Path to the configuration folder
/// @return Pointer to the loaded MachineConfig structure, or NULL on failure
/// @note The caller is responsible for freeing the returned structure using free_array_machine_config.
/// @note This function will recursively search for JSON files in the specified folder and its subfolders.
/// @note The JSON files should contain machine configuration data in the expected format.
/// @note The function initializes the ArrayMachineConfig with a default capacity of 8.
void load_machine_config(const char* folder_path, ArrayMachineConfig* array_machine_config){
    
    Stack* stack;
    DIR* dir;
    //struct json_object* parsed_json;
    struct dirent* entry;
    char* currentPath;
    char* ext;
    char path[PATH_MAX];
    
    if (!folder_path || !array_machine_config) return;

    init_array_machine_config(array_machine_config, 8); // Initialize with a default capacity
    stack = create_stack();

    if (!stack) {
        fprintf(stderr, "Failed to create stack\n");
        free_array_machine_config(array_machine_config);
        return;
    }

    stack_push(stack, strdup(folder_path));

    while(!is_empty(stack)){

        currentPath = stack_pop(stack);
        dir = opendir(currentPath);

        if(!dir) {
            free(currentPath);
            continue;
        }

        while((entry = readdir(dir))) {

            snprintf(path, PATH_MAX, "%s/%s", currentPath, entry->d_name);

            if(entry->d_type == DT_DIR) {
                // Skip "." and ".." entries
                if(strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                    stack_push(stack, strdup(path));
                }
            } else if(entry->d_type == DT_REG) {
                // Load machine configuration from the file
                ext = strrchr(entry->d_name,'.');

                if (ext && strcmp(ext,".json") == 0){ 

                    struct json_object* parsed_json = json_object_from_file(path);
                    if (parsed_json) {
                        _parse_machine_config(parsed_json, array_machine_config);
                        // Ensure JSON object is properly released
                        int ref_count = json_object_put(parsed_json);
                    }
                }
            }
        }

        closedir(dir);
        free(currentPath);
    }
    
    destroy_stack(stack);
}

