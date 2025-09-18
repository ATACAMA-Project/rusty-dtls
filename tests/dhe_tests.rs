use rusty_dtls::AlertDescription;

use crate::shared::{C_MSGS_DFLT, Proxy, S_MSGS_DFLT, handshake_test};

mod shared;

#[cfg(not(all(feature = "_dhe", feature = "secp256r1")))]
compile_error!("These tests expect to run without dhe exchange");

#[test]
fn simple_handshake_dhe() {
    let mut proxy = Proxy::new();
    proxy
        .client_psk_exch_modes(false, true)
        .server_psk_exch_modes(false, true)
        .client_msgs(C_MSGS_DFLT)
        .server_msgs(S_MSGS_DFLT);
    handshake_test(proxy);
}

#[test]
fn no_hello_rt_sent_since_key_shares_available() {
    use rusty_dtls::NamedGroup;

    let mut proxy = Proxy::new();
    proxy
        .server_require_cookie(false)
        .client_psk_exch_modes(false, true)
        .server_psk_exch_modes(false, true)
        .client_offer_key_shares(&[NamedGroup::Secp256r1])
        .client_msgs(C_MSGS_DFLT - 1)
        .server_msgs(S_MSGS_DFLT - 1);
    handshake_test(proxy);
}

#[test]
fn request_key_share() {
    let mut proxy = Proxy::new();
    proxy
        .server_require_cookie(false)
        .client_psk_exch_modes(true, true)
        .server_psk_exch_modes(false, true)
        .client_offer_key_shares(&[])
        .client_msgs(C_MSGS_DFLT)
        .server_msgs(S_MSGS_DFLT);
    handshake_test(proxy);
}

#[test]
fn server_does_not_support_psk_exch() {
    let mut proxy = Proxy::new();
    proxy
        .server_require_cookie(false)
        .client_psk_exch_modes(true, false)
        .server_psk_exch_modes(false, true)
        .client_expect_abort(AlertDescription::HandshakeFailure)
        .client_msgs(1)
        .server_msgs(1);
    handshake_test(proxy);
}

#[test]
fn server_does_not_support_psk_dhe_exch() {
    let mut proxy = Proxy::new();
    proxy
        .server_require_cookie(false)
        .client_psk_exch_modes(false, true)
        .server_psk_exch_modes(true, false)
        .client_expect_abort(AlertDescription::HandshakeFailure)
        .client_msgs(1)
        .server_msgs(1);
    handshake_test(proxy);
}
