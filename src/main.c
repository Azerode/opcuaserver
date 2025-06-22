#include "../include/opcuaserver.h"
#include <signal.h>

static volatile UA_Boolean running = true;

static void stopHandler(int sig){
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Received signal %d. Stopping server",sig);
    running = false;
}

int main(int argc, char *argv[]) {

    UA_ByteString json_config = UA_BYTESTRING_NULL;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_Server *server = NULL;
    ArrayMachineConfig machine_config = {0};

    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    if(argc >= 3) {
        /* Load server config */
        json_config = loadFile(argv[1]);
        if(json_config.length == 0) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Failed to load server config from file: %s", argv[1]);
            return EXIT_FAILURE;
        }

        load_machine_config(argv[2], &machine_config);

    } else {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Missing argument. Argument are "
                     "<server-config.json5>");
        return EXIT_FAILURE;
    }

    server = UA_Server_newFromFile(json_config);
   
    retval = UA_Server_run(server, &running);
    retval |= UA_Server_delete(server);

    /* clean up */
    UA_ByteString_clear(&json_config);

    free_array_machine_config(&machine_config);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}