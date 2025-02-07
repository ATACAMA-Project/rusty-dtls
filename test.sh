# Build in release to check for parse errors
cargo build --example echo --features aes128gcm_sha256 --features async --release && \
cargo test --features aes128gcm_sha256 --lib && \
cargo test --features aes128gcm_sha256 --test tests -- --test-threads=1 && \
cargo test --features aes128gcm_sha256 --features async --test tests -- --test-threads=1
