#ifndef MAIN_H
#define MAIN_H

#include "opcuaserver.h"
#include <signal.h>
#include <getopt.h>

/// @brief usage message for the OPC UA server.
/// This message provides information on how to use the server, including available options
/// and their descriptions. It is displayed when the user requests help or when incorrect
/// command line arguments are provided.
char * usage = "Usage: opcuaserver [options] <config_file> <machine_config_folder>\n"
               "Options:\n"
               "  -c, --config <file>          Specify the server configuration file\n"
               "  -m, --machine-config <path> Specify the path containing machine configurations. It can be a folder or a single file.\n"
               "  -h, --help                  Display this help message\n";

/// @brief load all machine configurations from a specified folder or file.
/// @param server Pointer to the UA_Server instance.
/// @param path Path to the containing machine configuration files. it can be a folder or a single file.
/// @return UA_StatusCode indicating the success or failure of the operation.
/// This function reads all configuration files in the specified folder, parses them,
/// and adds the machine configurations to the server. It returns UA_STATUSCODE_GOOD on success
/// or an appropriate error code on failure.               
UA_StatusCode load_path_config(UA_Server *server, const char * path);

/// @brief Main entry point for the OPC UA server.
/// @param argc Argument count.
/// @param argv Argument vector.
/// @return Exit status.
/// This function initializes the server, processes command line options
/// and starts the server loop. It handles configuration files and machine configurations.
/// If the server fails to start or encounters an error, it returns a non-zero exit code
int main(int argc, char *argv[]);

#endif // MAIN_H