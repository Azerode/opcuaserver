# syntax=docker/dockerfile:1

# ---- build -----------------------------------------------------------------
# Release build with the workspace profile (fat LTO, one codegen unit, stripped).
# Set TARGET_CPU=native for a binary tuned to the build machine's CPU; keep the
# default for an image that runs on any x86_64 / aarch64 host.
ARG RUST_VERSION=1
FROM rust:${RUST_VERSION}-slim-bookworm AS build
ARG TARGET_CPU=
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ -n "$TARGET_CPU" ]; then export RUSTFLAGS="-C target-cpu=$TARGET_CPU"; fi \
    && cargo build --release --locked --bin fastua \
    && cp target/release/fastua /usr/local/bin/fastua \
    && mkdir -p /out/data/pki /out/data/history

# ---- runtime ---------------------------------------------------------------
# distroless/cc: glibc + libgcc only, no shell, runs as uid 65532.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /usr/local/bin/fastua /usr/local/bin/fastua
COPY config/machines /config
# Writable state (certificate store, history) owned by the nonroot user so a
# named volume mounted on /data inherits the right owner.
COPY --from=build --chown=65532:65532 /out/data /data
WORKDIR /data
VOLUME ["/data"]
EXPOSE 4840
ENTRYPOINT ["/usr/local/bin/fastua"]
CMD ["--config", "/config", "--pki", "/data/pki", "--listen", "0.0.0.0:4840"]
