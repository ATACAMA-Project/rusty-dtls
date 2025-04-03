![Tests](https://github.com/ATACAMA-Project/rusty-dtls/actions/workflows/rust.yml/badge.svg)

# rusty-dtls

Implementation of DTLS 1.3 ([RFC 9147](https://www.rfc-editor.org/rfc/rfc9147.html)) inspired by [tinydtls](https://github.com/eclipse-tinydtls/tinydtls).

Currently, only supports a PSK based handshake with `AES128GCM_SHA256`.

Provides a blocking and an `async` interface (enable feature `async`).
