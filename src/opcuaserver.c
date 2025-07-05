#include "../include/opcuaserver.h"

/// @brief Set the data value for a variable
/// @param attri The variable attributes to set
/// @param value The value to set
/// @param type The data type of the value
/// @note This function will set the value of the variable attributes and its data type.
/// If the value or type is NULL, it will log an error and return without modifying the attributes.
static inline void set_data_value(UA_VariableAttributes* attri, void* value, const UA_DataType* type) {
    if (value == NULL || type == NULL) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Value or type is NULL");
        return;
    }
    UA_Variant_setScalar(&attri->value, value, type);
    attri->dataType = type->typeId;
}

/// @brief Set the display name and description for a variable
/// @param attri The variable attributes to set
/// @param name The display name to set
static inline void set_display_info(UA_VariableAttributes* attri, char* name) {
    if (name == NULL) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Name is NULL");
        return;
    }
    attri->displayName = UA_LOCALIZEDTEXT("en-US", name);
    attri->description = UA_LOCALIZEDTEXT("en-US", name);
}

/// @brief Initialize a boolean variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the boolean variable to false and set the access level to read/write.
static inline void init_boolean_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_Boolean){false}), &UA_TYPES[UA_TYPES_BOOLEAN]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a signed byte variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the signed byte variable to 0 and set the access level to read/write.
static inline void init_sbyte_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_SByte){0}), &UA_TYPES[UA_TYPES_SBYTE]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a byte variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the byte variable to 0 and set the access level to read/write.
static inline void init_byte_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_Byte){0}), &UA_TYPES[UA_TYPES_BYTE]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a signed integer variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the signed integer variable to 0 and set the access level to read/write.
static inline void init_int16_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_Int16){0}), &UA_TYPES[UA_TYPES_INT16]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize an unsigned integer variable node
/// @param attri The variable attributes to set 
/// @note This function will set the initial value of the unsigned integer variable to 0 and set the access level to read/write.
static inline void init_uint16_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_UInt16){0}), &UA_TYPES[UA_TYPES_UINT16]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a signed integer variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the signed integer variable to 0 and set the access level to read/write.
static inline void init_int32_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_Int32){0}), &UA_TYPES[UA_TYPES_INT32]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize an unsigned integer variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the unsigned integer variable to 0 and set the access level to read/write.
static inline void init_uint32_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_UInt32){0}), &UA_TYPES[UA_TYPES_UINT32]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a signed integer variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the signed integer variable to 0 and set the access level to read/write.
static inline void init_int64_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_Int64){0}), &UA_TYPES[UA_TYPES_INT64]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize an unsigned integer variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the unsigned integer variable to 0 and
static inline void init_uint64_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_UInt64){0}), &UA_TYPES[UA_TYPES_UINT64]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a floating-point variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the floating-point variable to 0.0 and set the access level to read/write.
static inline void init_float_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_Float){0}), &UA_TYPES[UA_TYPES_FLOAT]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a double-precision floating-point variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the double-precision floating-point variable to 0.0 and set the access level to read/write.
static inline void init_double_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_Double){0}), &UA_TYPES[UA_TYPES_DOUBLE]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a string variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the string variable to an empty string and set the access level to read/write.
static inline void init_string_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_String){.length = 0, .data = NULL}), &UA_TYPES[UA_TYPES_STRING]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a date/time variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the date/time variable to 0 (epoch) and set the access level to read/write.
static inline void init_datetime_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_DateTime){0}), &UA_TYPES[UA_TYPES_DATETIME]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a GUID variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the GUID variable to a zeroed GUID and set the access level to read/write.
static inline void init_guid_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_Guid){0}), &UA_TYPES[UA_TYPES_GUID]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a byte string variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the byte string variable to an empty byte string and set the access level to read/write.
static inline void init_bytestring_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_ByteString){.length = 0, .data = NULL}), &UA_TYPES[UA_TYPES_BYTESTRING]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize an XML element variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the XML element variable to an empty XML element and set the access level to read/write.
static inline void init_xml_element_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_XmlElement){.length = 0, .data = NULL}), &UA_TYPES[UA_TYPES_XMLELEMENT]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a NodeId variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the NodeId variable to a zeroed NodeId and set the access level to read/write.
static inline void init_nodeid_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_NodeId){0}), &UA_TYPES[UA_TYPES_NODEID]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize an expanded NodeId variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the expanded NodeId variable to a zeroed expanded NodeId and set the access level to read/write.
static inline void init_expanded_nodeid_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_ExpandedNodeId){0}), &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a status code variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the status code variable to 0 (Good) and set the access level to read/write.
static inline void init_status_code_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_StatusCode){0}), &UA_TYPES[UA_TYPES_STATUSCODE]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a qualified name variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the qualified name variable to a zeroed qualified name and set the access level to read/write.
static inline void init_qualified_name_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_QualifiedName){}), &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a localized text variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the localized text variable to a zeroed localized text and set the access level to read/write.
static inline void init_localized_text_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_LocalizedText){}), &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize an extension object variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the extension object variable to a zeroed extension object and set the access level to read/write.
static inline void init_extension_object_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_ExtensionObject){}), &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

/// @brief Initialize a diagnostic info variable node
/// @param attri The variable attributes to set
/// @note This function will set the initial value of the diagnostic info variable to a zeroed diagnostic info and set the access level to read/write.
static inline void init_diagnostic_info_node(UA_VariableAttributes* attri) {
    set_data_value(attri, &((UA_DiagnosticInfo){}), &UA_TYPES[UA_TYPES_DIAGNOSTICINFO]);
    attri->accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
}

///@brief Load a file into a UA_ByteString.
///@param path The path to the file to load.
///@return A UA_ByteString containing the file contents, or an empty UA_ByteString if the file could not be read.
///@note The caller is responsible for freeing the memory of the UA_ByteString data using `UA_ByteString_clear`.
UA_ByteString load_file(const char *const path){
    UA_ByteString fileContents = UA_STRING_NULL;

    /* Open the file */
    FILE *fp = fopen(path, "rb");
    if(!fp) {
        errno = 0; /* We read errno also from the tcp layer... */
        return fileContents;
    }

    /* Get the file length, allocate the data and read */
    fseek(fp, 0, SEEK_END);
    fileContents.length = (size_t)ftell(fp);
    fileContents.data = (UA_Byte *)UA_malloc(fileContents.length * sizeof(UA_Byte));
    if(fileContents.data) {
        fseek(fp, 0, SEEK_SET);
        size_t read = fread(fileContents.data, sizeof(UA_Byte), fileContents.length, fp);
        if(read != fileContents.length)
            UA_ByteString_clear(&fileContents);
    } else {
        fileContents.length = 0;
    }
    fclose(fp);

    return fileContents; 
}

/// @brief Create a new namespace in the server
/// @param server Pointer to the UA_Server instance
/// @param namespaceName The name of the namespace to create
/// @return The numeric identifier of the created namespace, or 0 on failure
/// @note This function will create a new namespace in the server's address space and return its numeric identifier.
uint16_t create_namespace(UA_Server* server, const char* namespace){
    return UA_Server_addNamespace(server,namespace);
}


/// @brief Set the type attribute for a variable
/// @param type The type of the variable
/// @param attri The variable attributes to set
/// @note This function will initialize the variable attributes based on the type provided.
/// If the type is not recognized, it will log a warning and default to Int32.
void set_type_attribute(const char * type, UA_VariableAttributes* attri){
    if(type == NULL || attri == NULL) return;

    if(strcmp(type, "bool") == 0){
        init_boolean_node(attri);
    } else if (strcmp(type, "byte") == 0) {
        init_byte_node(attri);
    } else if (strcmp(type, "bytestring") == 0) {
        init_bytestring_node(attri);
    } else if (strcmp(type, "datetime") == 0) {
        init_datetime_node(attri);
    } else if (strcmp(type, "sbyte") == 0) {
        init_sbyte_node(attri);
    } else if (strcmp(type, "int16") == 0) {
        init_int16_node(attri);
    } else if (strcmp(type, "uint16") == 0) {
        init_uint16_node(attri);
    } else if (strcmp(type, "int32") == 0) {
        init_int32_node(attri);
    } else if (strcmp(type, "uint32") == 0) {
        init_uint32_node(attri);
    } else if (strcmp(type, "int64") == 0) {
        init_int64_node(attri);
    } else if (strcmp(type, "uint64") == 0) {
        init_uint64_node(attri);
    } else if (strcmp(type, "float") == 0) {
        init_float_node(attri);
    } else if (strcmp(type, "double") == 0) {
        init_double_node(attri);
    } else if (strcmp(type, "string") == 0) {
        init_string_node(attri);
    } else if (strcmp(type, "guid") == 0) {
        init_guid_node(attri);
    } else if (strcmp(type, "nodeid") == 0) {
        init_nodeid_node(attri);
    } else if (strcmp(type, "expandednodeid") == 0) {
        init_expanded_nodeid_node(attri);
    } else if (strcmp(type, "qualifiedname") == 0) {
        init_qualified_name_node(attri);
    } else if (strcmp(type, "localizedtext") == 0) {
        init_localized_text_node(attri);
    } else if (strcmp(type, "extensionobject") == 0) {
        init_extension_object_node(attri);
    } else if (strcmp(type, "diagnosticinfo") == 0) {
        init_diagnostic_info_node(attri);
    } else if (strcmp(type, "diagnosticinfo") == 0) {
        init_diagnostic_info_node(attri);
    } else if (strcmp(type, "statuscode") == 0) {
        init_status_code_node(attri);
    } else if (strcmp(type, "xml_element") == 0) {
        init_xml_element_node(attri);
    }
    else {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Unknown type '%s', using default Int32", type);
            // Default to Int32 if type is unknown
            attri->dataType = UA_TYPES[UA_TYPES_INT32].typeId;
    }
}


/// @brief Generate the nodes for each item in the server
/// @param server Pointer to the UA_Server instance
/// @param items Pointer to the ArrayItem structure containing the items
/// @param group_folder_id The NodeId of the folder to add the items to
/// @param index_namespace The namespace index to use for the new nodes
/// @return UA_StatusCode indicating the success or failure of the operation
/// @note This function will create a variable for each item based on its type and add it
/// to the specified group folder. If the item type is not recognized, it will log a warning
/// and skip the item.
UA_StatusCode generate_item_node(UA_Server* server, ArrayItem* items,UA_NodeId group_folder_id, uint16_t index_namespace){
    Item* item = NULL;
    UA_StatusCode retval;
    UA_VariableAttributes attr;

    if (server == NULL || items == NULL) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Server or items are NULL");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    for(size_t nb_item = 0; nb_item < items->count; nb_item++){
        item = items->items + nb_item;

        if(item == NULL){
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Item is NULL at index %d", nb_item);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        if(item->name == NULL || item->type == NULL) {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Item name or type is NULL at index %d", nb_item);
            continue; // Skip this item
        }

        attr = UA_VariableAttributes_default;
        set_display_info(&attr, item->name);
        set_type_attribute(item->type, &attr);

        retval = UA_Server_addVariableNode(server, 
        UA_NODEID_NULL, // Requested new node ID (NULL means server will assign a new one)
        group_folder_id, // Parent node ID
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), // Parent reference node ID
        UA_QUALIFIEDNAME(index_namespace, item->name), // Browse name
        UA_NS0ID(BASEDATAVARIABLETYPE), // Type definition ID (BaseDataVariableType)
        attr, NULL, NULL);

        if (retval != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Failed to create variable node for item '%s' at index %d: %s",
                         item->name, nb_item, UA_StatusCode_name(retval));
            return retval;
        }
    }

    return UA_STATUSCODE_GOOD;
}

/// @brief Generate the nodes for each group in the server
/// @param server Pointer to the UA_Server instance
/// @param groups Pointer to the ArrayGroup structure containing the groups
/// @param folderId The NodeId of the folder to add the groups to
/// @param index_namespace The namespace index to use for the new nodes
/// @return UA_StatusCode indicating the success or failure of the operation
/// @note This function will create a folder for each group and add the items to the group based on their type.
UA_StatusCode generate_group_nodes(UA_Server *server, ArrayGroup *groups, UA_NodeId folderId, uint16_t index_namespace){
    
    Group* group = NULL;
    UA_NodeId group_folder_id = UA_NODEID_NULL;
    UA_StatusCode retval;

    if (server == NULL || groups == NULL) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Server or groups are NULL");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    for(size_t nb_group = 0; nb_group < groups->count; nb_group++){
        
        group = groups->groups + nb_group;

        if(group == NULL) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Group is NULL at index %d", nb_group);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        if(group->name == NULL) {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Group name is NULL at index %d", nb_group);
            continue; // Skip this group
        }

        // Create a folder for the group
        UA_ObjectAttributes folderAttr = UA_ObjectAttributes_default;
        folderAttr.displayName = UA_LOCALIZEDTEXT("en-US", group->name);

        retval = UA_Server_addObjectNode(server,
            UA_NODEID_NULL, // Requested new node ID (NULL means server will assign a new one)
            folderId, // Parent node ID
            UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), // Reference type ID (Organizes)
            UA_QUALIFIEDNAME(index_namespace, group->name), // Browse name
            UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE), // Type definition ID (FolderType)
            folderAttr, NULL, &group_folder_id);

        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Failed to create folder for group '%s' at index %d: %s",
                         group->name, nb_group, UA_StatusCode_name(retval));
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        retval = generate_item_node(server, &group->items, group_folder_id, index_namespace);
        
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Failed to generate item nodes for group '%s' at index %d: %s",
                         group->name, nb_group, UA_StatusCode_name(retval));
            return retval;
        }

    }

    return UA_STATUSCODE_GOOD;
}


/// @brief Add a machine configuration to the server
/// @param server Pointer to the UA_Server instance
/// @param config Pointer to the MachineConfig structure to add
/// @note This function will create the necessary nodes in the server address space based on the configuration provided.
UA_StatusCode add_machine_config(UA_Server *server, ArrayMachineConfig *config){
    
    MachineConfig * machine_config = NULL;
    uint16_t index_namespace = 0;
    UA_NodeId folderId = UA_NODEID_NULL;
    UA_ObjectAttributes folderAttr;
    UA_StatusCode retval;

    if (server == NULL || config == NULL){
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Server or configuration is NULL");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    for(size_t nb_config = 0; nb_config < config->count; nb_config++){
        machine_config = config->configs + nb_config;

        if(machine_config == NULL) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Machine configuration is NULL at index %d", nb_config);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        if (machine_config->name == NULL) {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Machine name is NULL at index %d", nb_config);
            continue;
        }

        index_namespace = create_namespace(server, machine_config->name);

        folderAttr = UA_ObjectAttributes_default;
        folderAttr.displayName = UA_LOCALIZEDTEXT("en-US", machine_config->name);

        retval = UA_Server_addObjectNode(server,
            UA_NODEID_NULL, // Requested new node ID (NULL means server will assign a new one)
            UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), // Reference type ID (Organizes)
            UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), // Reference type ID (Organizes)
            UA_QUALIFIEDNAME(index_namespace, machine_config->name), // Browse name
            UA_NODEID_NUMERIC(0,UA_NS0ID_FOLDERTYPE), // Type definition ID (FolderType)
            folderAttr, NULL, &folderId);

        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Failed to create folder for machine '%s' at index %d: %s",
                         machine_config->name, nb_config, UA_StatusCode_name(retval));
            continue;
        }

        generate_group_nodes(server, &machine_config->groups, folderId, index_namespace);
    }

    return UA_STATUSCODE_GOOD;
}