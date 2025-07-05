#include "../include/main.h"

static volatile UA_Boolean running = true;

static void stopHandler(int sig){
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Received signal %d. Stopping server",sig);
    running = false;
}

static struct option long_options[] = {
    {"config", 1, 0, 'c'},
    {"machine-config", 1, 0, 'm'},
    {"help", 0,0,'h'},
    {0, 0, 0, 0}
};

static int option_index = 0;



/// @brief load all machine configurations from a specified folder.
/// @param server Pointer to the UA_Server instance.
/// @param folder Path to the folder containing machine configuration files.
/// @return UA_StatusCode indicating the success or failure of the operation.
/// This function reads all configuration files in the specified folder, parses them,
/// and adds the machine configurations to the server. It returns UA_STATUSCODE_GOOD on success
/// or an appropriate error code on failure.               
UA_StatusCode load_path_config(UA_Server *server, const char * path){
    
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    ArrayMachineConfig machine_config = {0};

    if (server == NULL || path == NULL) return UA_STATUSCODE_BADINVALIDARGUMENT;

    load_machine_config(path, &machine_config);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Loaded %zu machine configurations from path: %s\n", 
            machine_config.count, path);

    retval =  add_machine_config(server, &machine_config);

    free_array_machine_config(&machine_config);

    return retval;
}


int main(int argc, char *argv[]) {

    UA_ByteString json_config = UA_BYTESTRING_NULL;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_Server *server = NULL;
    char c;
    char* config_file = NULL;
    char* machine_config_folder = NULL;

    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    do {
        c = getopt_long(argc, argv,"hc:m:",long_options, &option_index);
        printf("Option: %d, optarg: %s\n", c, optarg);
        switch(c) {
            case 'c': 
                config_file = optarg;
                UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,"Using server config file: %s\n", config_file);
                break;
            case 'm': 
                machine_config_folder = optarg;
                UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,"Using machine config folder: %s\n", machine_config_folder);
                break;
            case 'h':
                printf("%s", usage);
                return EXIT_SUCCESS;
            case -1: // No more options
                break;
            case 255:
                break;
            default: 
                UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                             "Unknown option: %c", c);
                printf("%s", usage);
                return EXIT_FAILURE;
        }
    } while (c != -1 && c != 255);

    /* Load server config */
    json_config = load_file(config_file);

    if(json_config.length == 0) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Failed to load server config from file: %s", argv[1]);
        return EXIT_FAILURE;
    }

    server = UA_Server_newFromFile(json_config);
   
    retval = load_path_config(server, machine_config_folder);

    if (retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Error during loading machine configuration: %d",retval);
        UA_ByteString_clear(&json_config);
        return EXIT_FAILURE;
    }

    retval = UA_Server_run(server, &running);
    retval |= UA_Server_delete(server);

    /* clean up */
    UA_ByteString_clear(&json_config);

    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}