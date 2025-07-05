# Build stage
FROM alpine:3.21.3 AS build

RUN apk add --no-cache \
    cmake\
    gcc \
    git \
    musl-dev \
    mbedtls-dev \
    python3 \
    py3-pip \
    make \
    valgrind \
    linux-headers \
    && rm -rf /var/cache/apk/*

# Create symlinks for standard include paths
RUN mkdir -p /usr/include/bits && \
ln -s /usr/include/limits.h /usr/include/bits/stdio_lim.h

# Build application stage
WORKDIR /app
COPY makefile .
COPY include/ include/
COPY tests/ tests/
COPY src/ src/

RUN make test-valgrind

# Final stage
FROM alpine:3.21.3

# Install runtime dependencies
RUN apk add --no-cache musl mbedtls \
    && rm -rf /var/cache/apk/* && \
    mkdir -p /etc/ssl/opcua-server && \
    mkdir -p /etc/ssl/opcua-server/privateKey

COPY --from=build /app/bin/opcuaserver /app/
COPY --from=build /app/bin/lib/ /app/lib/

WORKDIR /app

EXPOSE 62541

ENTRYPOINT ["./opcuaserver", "-c", "/app/config/server/config.json5", "-m","/app/config/machine"]