#ifndef OPCUASERVER_H
#define OPCUASERVER_H

#include "common.h"
#include "machine_config.h"

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server_config_file_based.h>


///@brief Load a file into a UA_ByteString.
///@param path The path to the file to load.
///@return A UA_ByteString containing the file contents, or an empty UA_ByteString if the file could not be read.
///@note The caller is responsible for freeing the memory of the UA_ByteString data using `UA_ByteString_clear`.
UA_ByteString load_file(const char *const path);

/// @brief Generate the nodes for each group in the server
/// @param server Pointer to the UA_Server instance
/// @param groups Pointer to the ArrayGroup structure containing the groups
/// @param folderId The NodeId of the folder to add the groups to
/// @param index_namespace The namespace index to use for the new nodes
/// @return UA_StatusCode indicating the success or failure of the operation
/// @note This function will create a folder for each group and add the items to the group based on their type.
UA_StatusCode generate_group_nodes(UA_Server *server, ArrayGroup *groups, UA_NodeId folderId, uint16_t index_namespace);

/// @brief Add a machine configuration to the server
/// @param server Pointer to the UA_Server instance
/// @param config Pointer to the MachineConfig structure to add
/// @note This function will create the necessary nodes in the server address space based on the configuration provided.
UA_StatusCode add_machine_config(UA_Server *server, ArrayMachineConfig *config);

#endif // OPCUASERVER_H