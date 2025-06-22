### Build Verification Commands

#### macOS
1. **Check Dynamic Library Dependencies**
```bash
otool -L bin/opcuaserver
```
Expected output:
```
bin/opcuaserver:
    @rpath/libopen62541.dylib
    @rpath/libjson-c.dylib
    /usr/lib/libc++.1.dylib
```

2. **Verify RPATH Settings**
```bash
otool -l bin/opcuaserver | grep -A2 LC_RPATH
```
Expected output:
```
          cmd LC_RPATH
      cmdsize 32
         path @executable_path/lib
```

#### Linux
1. **Check Dynamic Library Dependencies**
```bash
ldd bin/opcuaserver
```
Expected output:
```
    libopen62541.so => ./lib/libopen62541.so
    libjson-c.so => ./lib/libjson-c.so
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
```

2. **Verify RPATH Settings**
```bash
readelf -d bin/opcuaserver | grep RPATH
```
Expected output:
```
 0x000000000000001d (RPATH)  $ORIGIN/lib
```

#### Common Issues and Solutions

1. **Wrong RPATH**
```bash
# macOS fix
install_name_tool -add_rpath @executable_path/lib bin/opcuaserver

# Linux fix
patchelf --set-rpath '$ORIGIN/lib' bin/opcuaserver
```

2. **Missing Libraries**
```bash
# Verify library exists
ls -l bin/lib/libopen62541*
ls -l bin/lib/libjson-c*
```