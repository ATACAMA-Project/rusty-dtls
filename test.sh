set -e

# Build in release to check for parse errors
cargo build --example echo --features aes128gcm_sha256,secp256r1,async --release

cargo build --example echo --no-default-features --features aes128gcm_sha256,secp256r1,time_size_u64

cargo test --features aes128gcm_sha256 --lib
cargo test --features aes128gcm_sha256 --test basic_tests
cargo test --features aes256gcm_sha384 --test basic_tests

cargo test --features aes128gcm_sha256 --features async --test basic_tests

cargo test --features aes128gcm_sha256 --features secp256r1 --test dhe_tests
