# Technical Documentation - OPC UA Server

## Build System Documentation

### Makefile Structure

#### 1. Compiler Configuration
```makefile
CC = gcc
CFLAGS = -Wall -Wextra \
         -I./src/include \
         -I$(DEPS_DIR)/open62541/include
```
- `CC`: Defines the C compiler
- `CFLAGS`: Compiler flags
  - `-Wall -Wextra`: Enable important warnings
  - `-I`: Include directories for headers

#### 2. Linker Configuration
```makefile
LDFLAGS = -L$(DEPS_DIR)/open62541/build/bin -lopen62541
```
- `-L`: Library search paths
- `-l`: Libraries to link against

#### 3. Dynamic Library Handling
```makefile
# macOS specific
LDFLAGS += -Wl,-rpath,@executable_path/lib

# Linux specific
LDFLAGS += -Wl,-rpath,'$$ORIGIN/lib'
```
- `rpath`: Runtime path for shared libraries
- `@executable_path`: macOS path relative to executable
- `$$ORIGIN`: Linux path relative to executable

### Project Structure

```
project/
├── src/           # Source files
├── include/       # Header files
├── build/         # Compilation artifacts
├── bin/           # Final executables
└── deps/          # Dependencies
```

### Build Process

1. **Dependencies Resolution**
   ```bash
   make dependencies
   ```
   - Clones and builds open62541
   - Clones and builds json-c

2. **Compilation**
   ```bash
   make
   ```
   - Creates necessary directories
   - Compiles source files into objects
   - Links objects with libraries

3. **Cleaning**
   ```bash
   make clean      # Remove build artifacts
   make clean-all  # Remove everything including dependencies
   ```

### Common Issues

1. **Library Not Found**
   ```bash
   dyld: Library not loaded: @rpath/libopen62541.dylib
   ```
   Solution: Check if libraries are in `bin/lib/` directory

2. **Header Not Found**
   ```
   fatal error: 'open62541/server.h' file not found
   ```
   Solution: Verify include paths in `CFLAGS`

### Development Workflow

1. **Clean Build**
   ```bash
   make clean-all
   make
   ```

2. **Incremental Build**
   ```bash
   make
   ```

3. **Running the Server**
   ```bash
   ./bin/opcuaserver config.json
   ```

### Dependencies Management

#### open62541
- OPC UA implementation
- Built as shared library
- Required headers:
  - `open62541/server.h`
  - `open62541/client.h`

#### json-c
- JSON parser
- Built as shared library
- Required headers:
  - `json-c/json.h`

### Cross-Platform Considerations

#### macOS
- Uses `.dylib` extension for shared libraries
- Requires `@executable_path` for rpath

#### Linux
- Uses `.so` extension for shared libraries
- Requires `$ORIGIN` for rpath