FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build -p revvault-cli --locked --release --jobs 2

# Artifact only: consumers provide the glibc runtime and their fixed OS account.
# No policy, identity, ciphertext, home directory or operator configuration.
FROM scratch AS runtime
COPY --from=builder /app/target/release/revvault /usr/local/bin/revvault
