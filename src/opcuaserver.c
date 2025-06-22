#include "../include/opcuaserver.h"


///@brief Load a file into a UA_ByteString.
///@param path The path to the file to load.
///@return A UA_ByteString containing the file contents, or an empty UA_ByteString if the file could not be read.
///@note The caller is responsible for freeing the memory of the UA_ByteString data using `UA_ByteString_clear`.
UA_ByteString loadFile(const char *const path){
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


/// @brief Add a machine configuration to the server
/// @param server Pointer to the UA_Server instance
/// @param config Pointer to the MachineConfig structure to add
/// @note This function will create the necessary nodes in the server address space based on the configuration provided.
void AddMachineConfigToServer(UA_Server *server, ArrayMachineConfig *config){

}