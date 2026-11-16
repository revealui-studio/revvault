FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,id=revealfleet-native-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=revealfleet-native-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=revealfleet-native-cargo-target,target=/app/target \
    cargo build -p revvault-cli --locked --jobs 2 \
    && cargo test -p revvault-core --locked --jobs 2 --features native-service-tests \
       --test service_provisioning_native --no-run --message-format=json > /tmp/revealfleet-native-artifacts.json \
    && fixture="$(sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' /tmp/revealfleet-native-artifacts.json)" \
    && case "$fixture" in /app/target/debug/deps/service_provisioning_native-*) ;; *) exit 1 ;; esac \
    && test -f "$fixture" \
    && install -m 0755 "$fixture" /usr/local/bin/revealfleet-native-service-tests \
    && install -m 0755 /app/target/debug/revvault /usr/local/bin/revvault \
    && rm /tmp/revealfleet-native-artifacts.json
CMD ["/usr/local/bin/revealfleet-native-service-tests", "--nocapture"]
