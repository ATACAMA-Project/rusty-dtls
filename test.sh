# Run in release to check for parse errors
cargo build --example echo --features aes128gcm_sha256 --release
cargo test --features aes128gcm_sha256 -- --test-threads=1
cargo test --features aes128gcm_sha256 --features async -- --test-threads=1
