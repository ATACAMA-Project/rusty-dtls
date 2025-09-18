use rusty_dtls::{AlertDescription, HashFunction, Psk};

use crate::shared::{C_MSGS_DFLT, Proxy, S_MSGS_DFLT, handshake_test};

mod shared;

#[cfg(feature = "_dhe")]
compile_error!("These tests expect to run without dhe exchange");

#[test]
fn simple_handshake() {
    let mut proxy = Proxy::new();
    proxy.client_msgs(C_MSGS_DFLT).server_msgs(S_MSGS_DFLT);
    handshake_test(proxy)
}

#[test]
fn multiple_psks() {
    let mut proxy = Proxy::new();
    proxy
        .server_require_cookie(false)
        .client_psks(&[
            Psk::new(&[3], &[1], HashFunction::Sha256),
            Psk::new(&[5], &[1], HashFunction::Sha256),
        ])
        .server_psks(&[
            Psk::new(&[5], &[1], HashFunction::Sha256),
            Psk::new(&[4], &[1], HashFunction::Sha256),
        ])
        .client_msgs(C_MSGS_DFLT - 1)
        .server_msgs(S_MSGS_DFLT - 1);
    handshake_test(proxy);
}

#[test]
fn empty_psk_id() {
    let mut proxy = Proxy::new();
    proxy
        .server_require_cookie(false)
        .client_psks(&[Psk::new(&[], &[1], HashFunction::Sha256)])
        .server_psks(&[Psk::new(&[1], &[1], HashFunction::Sha256)])
        .client_expect_abort(AlertDescription::DecodeError)
        .client_msgs(1)
        .server_msgs(1);
    handshake_test(proxy);
}

#[test]
fn no_hello_rt_sent_since_no_cookie_required() {
    let mut proxy = Proxy::new();
    proxy
        .server_require_cookie(false)
        .client_msgs(C_MSGS_DFLT - 1)
        .server_msgs(S_MSGS_DFLT - 1);
    handshake_test(proxy);
}

mod transport_issues {
    use crate::shared::*;

    #[test]
    fn duplicate_client_hello_1() {
        let mut proxy = Proxy::new();
        proxy
            .client_action(0, Action::Duplicate)
            .client_msgs(C_MSGS_DFLT)
            .server_msgs(S_MSGS_DFLT + 1);
        handshake_test(proxy)
    }

    #[test]
    fn reorder_encrypted_extensions() {
        let mut proxy = Proxy::new();
        proxy
            .server_action(2, Action::Store)
            .server_action(4, Action::SendStored)
            .client_msgs(C_MSGS_DFLT)
            .server_msgs(S_MSGS_DFLT);

        handshake_test(proxy)
    }

    #[test]
    fn lost_client_hello_1() {
        let mut proxy = Proxy::new();
        proxy
            .client_action(0, Action::Drop)
            .client_msgs(C_MSGS_DFLT + 1)
            .server_msgs(S_MSGS_DFLT);
        handshake_test(proxy)
    }

    #[test]
    fn lost_client_hello_1_multiple_times() {
        let mut proxy = Proxy::new();
        proxy
            .client_action(0, Action::Drop)
            .client_action(1, Action::Drop)
            .client_msgs(C_MSGS_DFLT + 2)
            .server_msgs(S_MSGS_DFLT);

        handshake_test(proxy)
    }

    #[test]
    fn lost_hello_retry() {
        let mut proxy = Proxy::new();
        proxy
            .server_action(0, Action::Drop)
            .client_msgs(C_MSGS_DFLT + 1)
            .server_msgs(S_MSGS_DFLT + 1);

        handshake_test(proxy)
    }

    #[test]
    fn lost_client_hello_2() {
        let mut proxy = Proxy::new();
        proxy
            .client_action(1, Action::Drop)
            .client_msgs(C_MSGS_DFLT + 1)
            .server_msgs(S_MSGS_DFLT);

        handshake_test(proxy)
    }

    #[test]
    fn lost_server_hello() {
        let mut proxy = Proxy::new();
        proxy
            .server_action(1, Action::Drop)
            .client_msgs(C_MSGS_DFLT + 1)
            .server_msgs(S_MSGS_DFLT + 3);
        handshake_test(proxy)
    }

    #[test]
    fn lost_encrypted_extensions() {
        let mut proxy = Proxy::new();
        proxy
            .server_action(2, Action::Drop)
            .client_msgs(C_MSGS_DFLT)
            .server_msgs(S_MSGS_DFLT + 3);
        handshake_test(proxy)
    }

    #[test]
    fn lost_server_finished() {
        let mut proxy = Proxy::new();
        proxy
            .server_action(3, Action::Drop)
            .client_msgs(C_MSGS_DFLT)
            .server_msgs(S_MSGS_DFLT + 3);
        handshake_test(proxy)
    }

    #[test]
    fn lost_client_finished() {
        let mut proxy = Proxy::new();
        proxy
            .client_action(2, Action::Drop)
            .client_msgs(C_MSGS_DFLT + 1)
            .server_msgs(S_MSGS_DFLT + 3);

        handshake_test(proxy)
    }

    #[test]
    fn lost_ack() {
        let mut proxy = Proxy::new();
        proxy
            .server_action(4, Action::Drop)
            .client_msgs(C_MSGS_DFLT + 1)
            .server_msgs(S_MSGS_DFLT + 1);

        handshake_test(proxy)
    }

    #[test]
    fn implicit_ack_using_app_data() {
        let mut proxy = Proxy::new();
        proxy
            .server_action(4, Action::Drop)
            .server_send_app_data(true)
            .client_msgs(C_MSGS_DFLT)
            .server_msgs(S_MSGS_DFLT + 1);
        handshake_test(proxy);
    }
}

mod manipulated_messages {
    use crate::shared::*;
    #[test]
    fn encrypted_extensions_header_bitflip() {
        let mut proxy = Proxy::new();
        proxy
            .server_action(2, Action::BitFlip(0)) // Make the client think its not a EncryptedRecord
            .client_msgs(C_MSGS_DFLT)
            .server_msgs(S_MSGS_DFLT + 3);
        handshake_test(proxy)
    }

    #[test]
    fn encrypted_extensions_payload_bitflip() {
        let mut proxy = Proxy::new();
        proxy
            .server_action(2, Action::BitFlip(5 * 8)) // Make the client think its not a EncryptedRecord
            .client_msgs(C_MSGS_DFLT)
            .server_msgs(S_MSGS_DFLT + 3);
        handshake_test(proxy)
    }

    #[test]
    fn client_hello_1_manip_length_to_long() {
        let mut proxy = Proxy::new();
        proxy
            .client_action(
                0,
                Action::UpdatePlaintextHeader(HeaderUpdate::NewLength(500)),
            )
            .client_msgs(C_MSGS_DFLT + 1)
            .server_msgs(S_MSGS_DFLT);
        handshake_test(proxy);
    }

    #[test]
    fn client_hello_1_manip_length_to_short() {
        let mut proxy = Proxy::new();
        proxy
            .client_action(
                0,
                Action::UpdatePlaintextHeader(HeaderUpdate::NewLength(20)),
            )
            .client_msgs(C_MSGS_DFLT + 1)
            .server_msgs(S_MSGS_DFLT);
        handshake_test(proxy);
    }

    #[test]
    fn client_hello_1_truncate() {
        let mut proxy = Proxy::new();
        proxy
            .client_action(0, Action::Truncate(50))
            .client_msgs(C_MSGS_DFLT + 1)
            .server_msgs(S_MSGS_DFLT);
        handshake_test(proxy);
    }
}
