# OPC UA Server Project

## Description
A C-based OPC UA Server implementation using open62541 library and JSON-C for configuration.

## Prerequisites

### macOS
```bash
brew install cmake
brew install mbedtls
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get install build-essential cmake git libmbedtls-dev
```

## Building from Source

1. Clone the repository
```bash
git clone <repository-url>
cd OpcUaServer
```

2. Build the project
```bash
make
```

This will:
- Create necessary directories
- Download and build dependencies (open62541 and json-c)
- Compile the server

## Project Structure
```
OpcUaServer/
├── src/           # Source files
├── bin/           # Compiled binary and libraries
│   ├── lib/       # Shared libraries (.dylib/.so)
│   └── opcuaserver
├── build/         # Build artifacts
└── deps/          # Dependencies
    ├── open62541/ # OPC UA stack
    └── json-c/    # JSON parser
```

## Usage

1. Run the server:
```bash
./bin/opcuaserver /path/to/config.json5
```

2. Configuration file example:
```json5
{
    "server": {
        "port": 62541,
        "hostname": "localhost"
    }
}
```

## Development

### Dependencies
- open62541 (OPC UA implementation)
- json-c (JSON parser)

### Building for Development
```bash
# Clean and rebuild everything
make clean-all
make

# Clean only build artifacts
make clean

# Rebuild
make rebuild
```

## License
MIT License

Copyright (c) 2025 Azerode

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
