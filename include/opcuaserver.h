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
UA_ByteString loadFile(const char *const path);

/// @brief Add a machine configuration to the server
/// @param server Pointer to the UA_Server instance
/// @param config Pointer to the MachineConfig structure to add
/// @note This function will create the necessary nodes in the server address space based on the configuration provided.
void AddMachineConfigToServer(UA_Server *server, ArrayMachineConfig *config);

#endif // OPCUASERVER_H