# Rust Conventions

- Use `thiserror` for library error types, `anyhow` for binaries
- Wrap decrypted secrets in `secrecy::SecretString` — never log or display raw values
- Use `age` crate (0.11.x) for all encryption — no custom crypto
- Prefer `walkdir` over manual `read_dir` recursion
- Run `cargo clippy --workspace` and `cargo fmt --check` before committing
- All public API functions should have doc comments
- Integration tests that touch the real store go in `tests/` with `#[ignore]` by default
