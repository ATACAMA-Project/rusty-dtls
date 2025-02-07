use core::panic;
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use rand::{RngCore, SeedableRng};
use rusty_dtls::{HandshakeSlot, HashFunction, NetQueue, Psk};

#[cfg(not(feature = "async"))]
use {
    rusty_dtls::{ConnectionId, DtlsPoll, DtlsStack},
    std::{cell::Cell, ops::Range, time::Instant},
};

#[cfg(feature = "async")]
use {embedded_nal_async::UdpStack, std::net::Ipv4Addr};

use log::{debug, info};

/// CH + Cookie + management info: (1B Flag, 8B Length)

#[derive(Clone, Copy)]
pub enum HeaderUpdate {
    NewLength(u16),
}

#[derive(Clone, Copy)]
pub enum Action {
    Drop,
    BitFlip(usize),
    UpatePlaintextHeader(HeaderUpdate),
    Store,
    SendStored,
    Duplicate,
}

impl Action {
    fn run(
        &self,
        proxy: &mut Proxy,
        addr: &SocketAddr,
        recv_addr: &SocketAddr,
        recv_buf: &mut [u8],
    ) -> bool {
        match self {
            Action::SendStored => panic!(),
            Action::BitFlip(pos) => {
                debug!("Flip bit {} in {addr:?} => {recv_addr:?}", pos);
                recv_buf[pos / 8] ^= 1 << (7 - (pos % 8));
                false
            }
            Action::UpatePlaintextHeader(HeaderUpdate::NewLength(len)) => {
                debug!("Update length to {} in {addr:?} => {recv_addr:?}", len);
                recv_buf[11..=12].copy_from_slice(&len.to_be_bytes());
                false
            }
            Action::Drop => {
                debug!("Drop {addr:?} => {recv_addr:?}");
                true
            }
            Action::Store => {
                debug!("Store {addr:?} => {recv_addr:?}");
                if addr == &proxy.client {
                    assert!(proxy.client_stored.is_none());
                    proxy.client_stored = Some((*recv_addr, recv_buf.to_vec()));
                } else {
                    assert!(proxy.server_stored.is_none());
                    proxy.server_stored = Some((*recv_addr, recv_buf.to_vec()));
                }
                true
            }
            Action::Duplicate => {
                debug!("Duplicate {addr:?} => {recv_addr:?}");
                proxy.socket.send_to(recv_buf, recv_addr).unwrap();
                false
            }
        }
    }
}

pub struct Proxy {
    client_action_index: u32,
    server_action_index: u32,
    client_stored: Option<(SocketAddr, Vec<u8>)>,
    server_stored: Option<(SocketAddr, Vec<u8>)>,
    client: SocketAddr,
    server: SocketAddr,
    socket: UdpSocket,
    client_actions: HashMap<u32, Action>,
    server_actions: HashMap<u32, Action>,
    allowed_client_msgs: i32,
    allowed_server_msgs: i32,
    stopper: Arc<Mutex<bool>>,
}

impl Default for Proxy {
    fn default() -> Self {
        Self::new()
    }
}

impl Proxy {
    pub fn new() -> Self {
        Self {
            client_action_index: 0,
            server_action_index: 0,
            client_stored: None,
            server_stored: None,
            client: SocketAddr::from(([127, 0, 0, 1], CLIENT_PORT)),
            server: SocketAddr::from(([127, 0, 0, 1], SERVER_PORT)),
            socket: UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], PROXY_PORT))).unwrap(),
            client_actions: HashMap::new(),
            server_actions: HashMap::new(),
            allowed_client_msgs: i32::MAX,
            allowed_server_msgs: i32::MAX,
            stopper: Arc::new(Mutex::new(false)),
        }
    }
    pub fn max_client_msgs(&mut self, max_msg: u16) -> &mut Self {
        self.allowed_client_msgs = max_msg as i32;
        self
    }

    pub fn client_action(&mut self, package_number: u32, action: Action) -> &mut Self {
        self.client_actions.insert(package_number, action);
        self
    }

    pub fn max_server_msgs(&mut self, max_msg: u16) -> &mut Self {
        self.allowed_server_msgs = max_msg as i32;
        self
    }

    pub fn server_action(&mut self, package_number: u32, action: Action) -> &mut Self {
        self.server_actions.insert(package_number, action);
        self
    }

    pub fn run(mut self) -> Stopper {
        let stopper = self.stopper.clone();
        let thread = thread::Builder::new()
            .name("Proxy".to_string())
            .spawn(move || {
                let mut buffer = [0; 500];
                self.socket
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                while !*self.stopper.try_lock().unwrap() {
                    assert!(
                        self.allowed_client_msgs >= 0,
                        "Client sent more messages than allowed"
                    );
                    assert!(
                        self.allowed_server_msgs >= 0,
                        "Server sent more messages than allowed"
                    );

                    let client_action = self.client_actions.get(&self.client_action_index).copied();
                    let server_action = self.server_actions.get(&self.server_action_index).copied();

                    if let Some(Action::SendStored) = client_action {
                        let (addr, buf) = self.client_stored.take().unwrap();
                        debug!("Send stored {:?} => {addr:?}", &self.client);
                        self.socket.send_to(&buf, addr).unwrap();
                        self.client_action_index += 1;
                        continue;
                    }
                    if let Some(Action::SendStored) = server_action {
                        let (addr, buf) = self.server_stored.take().unwrap();
                        debug!("Send stored {:?} => {addr:?}", &self.server);
                        self.socket.send_to(&buf, addr).unwrap();
                        self.server_action_index += 1;
                        continue;
                    }

                    let Ok((read, addr)) = self.socket.recv_from(&mut buffer) else {
                        continue;
                    };

                    if addr == self.client {
                        let recv_addr = self.server;
                        self.allowed_client_msgs -= 1;
                        self.client_action_index += 1;
                        if let Some(action) = client_action {
                            if action.run(&mut self, &addr, &recv_addr, &mut buffer[..read]) {
                                continue;
                            }
                        }
                        debug!("Forwarding {addr:?} => {recv_addr:?} {read}");
                        self.socket.send_to(&buffer[..read], recv_addr).unwrap();
                    } else if addr == self.server {
                        let recv_addr = self.client;
                        self.allowed_server_msgs -= 1;
                        self.server_action_index += 1;
                        if let Some(action) = server_action {
                            if action.run(&mut self, &addr, &recv_addr, &mut buffer[..read]) {
                                continue;
                            }
                        }
                        debug!("Forwarding {addr:?} => {recv_addr:?} {read}");
                        self.socket.send_to(&buffer[..read], recv_addr).unwrap();
                    } else {
                        panic!()
                    }
                }
            })
            .unwrap();
        Stopper { stopper, thread }
    }
}

pub struct Stopper {
    stopper: Arc<Mutex<bool>>,
    thread: JoinHandle<()>,
}

impl Stopper {
    pub fn stop(self) {
        *self.stopper.lock().unwrap() = true;
        self.thread.join().unwrap();
    }
}

#[cfg(feature = "async")]
async fn run_handshake_async(
    own_port: u16,
    peer_port: u16,
    server: bool,
    server_send_app_data: bool,
) {
    use rusty_dtls::DtlsStackAsync;

    let mut net_queue = NetQueue::new();
    let mut staging_buffer = [0; 256];

    let seed = rand::thread_rng().next_u64();
    info!("[{own_port}] Using seed {seed}");
    let mut rand = rand::rngs::StdRng::seed_from_u64(seed);

    let psks = [Psk::new(&[123], &[1, 2, 3, 4, 5], HashFunction::Sha256)];

    let delay = linux_embedded_hal::Delay;
    let clock = std_embedded_time::StandardClock::default();
    let udp_stack = std_embedded_nal_async::Stack;
    let (addr, socket) = udp_stack
        .bind_single(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            own_port,
        ))
        .await
        .unwrap();

    let mut stack = DtlsStackAsync::<'_, _, _, _, 10>::new(
        &mut rand,
        &mut staging_buffer,
        delay,
        clock,
        socket,
        addr,
    )
    .unwrap();
    let mut handshakes = Vec::new();
    if server {
        handshakes.push(HandshakeSlot::new(&psks, &mut net_queue));
    } else {
        handshakes.push(HandshakeSlot::new(&psks, &mut net_queue));
        assert!(stack.open_connection(
            &mut handshakes[0],
            &format!("127.0.0.1:{}", peer_port).parse().unwrap()
        ));
    }

    loop {
        let e = stack.read(&mut handshakes, 5000).await;
        match e.unwrap() {
            rusty_dtls::Event::AppData(_, range) => {
                if &stack.staging_buffer()[range] == "Client App Data".as_bytes() {
                    return;
                }
            }
            rusty_dtls::Event::OpenedConnection => {
                let id = handshakes[0].try_take_connection_id().unwrap();
                info!("[{own_port}] Got connection id: {:?}", id);
                if server && server_send_app_data {
                    stack
                        .send_dtls_packet(id, "Server App Data".as_bytes())
                        .await
                        .unwrap();
                }
                if !server {
                    stack
                        .send_dtls_packet(id, "Client App Data".as_bytes())
                        .await
                        .unwrap();
                    return;
                }
            }
            _ => {}
        };
    }
}

#[cfg(not(feature = "async"))]
fn run_handshake(own_port: u16, peer_port: u16, server: bool, server_send_app_data: bool) {
    use log::error;

    let socket = Mutex::new(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], own_port))).unwrap());
    let mut send_to_peer = |addr: &SocketAddr, buf: &[u8]| {
        debug!("[{own_port}] Send message. Size: {}", buf.len());
        socket.lock().unwrap().send_to(buf, addr).unwrap();
    };
    let got_app_data = Cell::new(false);
    let mut handle_app_data =
        |_id: ConnectionId, data: Range<usize>, stack: &mut DtlsStack<'_, 10>| {
            if &stack.staging_buffer()[data] == "Client App Data".as_bytes() {
                got_app_data.replace(true);
            } else if server {
                panic!("Server got wrong app data");
            }
        };

    let mut net_queue = NetQueue::new();
    let mut staging_buffer = [0; 200];

    let seed = rand::thread_rng().next_u64();
    info!("[{own_port}] Using seed {seed}");
    let mut rand = rand::rngs::StdRng::seed_from_u64(seed);

    let psks = [Psk::new(&[123], &[1, 2, 3, 4, 5], HashFunction::Sha256)];
    let mut stack =
        DtlsStack::<10>::new(&mut rand, &mut staging_buffer, &mut send_to_peer).unwrap();

    let mut handshakes = Vec::new();
    if server {
        handshakes.push(HandshakeSlot::new(&psks, &mut net_queue));
    } else {
        handshakes.push(HandshakeSlot::new(&psks, &mut net_queue));
        assert!(stack.open_connection(
            &mut handshakes[0],
            &format!("127.0.0.1:{}", peer_port).parse().unwrap()
        ));
    }

    let start = Instant::now();
    loop {
        let poll = stack.poll(&mut handshakes, start.elapsed().as_millis() as u64);
        if poll.is_err() {
            error!("[{own_port}] PollErr: {poll:?}");
        }
        assert!(poll.is_ok());
        let poll = poll.unwrap();
        match poll {
            DtlsPoll::WaitTimeoutMs(ms) => {
                debug!("[{own_port}] Wait {ms}");
                socket
                    .lock()
                    .unwrap()
                    .set_read_timeout(Some(Duration::from_millis(ms as u64)))
                    .unwrap();
            }
            DtlsPoll::Wait => {
                debug!("[{own_port}] Wait");
                socket.lock().unwrap().set_read_timeout(None).unwrap();
            }
            DtlsPoll::FinishedHandshake => {
                for hs in &mut handshakes {
                    let Some(id) = hs.try_take_connection_id() else {
                        continue;
                    };
                    info!("[{own_port}] Got connection id: {:?}", id);
                    if server && server_send_app_data {
                        stack.send_dtls_packet(id, "App Data".as_bytes()).unwrap();
                    }
                    if !server {
                        stack
                            .send_dtls_packet(id, "Client App Data".as_bytes())
                            .unwrap();
                        return;
                    }
                }
            }
        }
        let Ok((received, addr)) = socket.lock().unwrap().recv_from(stack.staging_buffer()) else {
            continue;
        };
        stack
            .handle_dtls_packet(&mut handshakes, &addr, received, &mut handle_app_data)
            .unwrap();
        if got_app_data.get() {
            return;
        }
    }
}

#[cfg(not(feature = "async"))]
fn run_server(send_app_data: bool) -> JoinHandle<()> {
    thread::Builder::new()
        .name("Server".to_string())
        .spawn(move || {
            run_handshake(SERVER_PORT, PROXY_PORT, true, send_app_data);
        })
        .unwrap()
}

#[cfg(not(feature = "async"))]
fn run_client() -> JoinHandle<()> {
    thread::Builder::new()
        .name("Client".to_string())
        .spawn(move || {
            run_handshake(CLIENT_PORT, PROXY_PORT, false, false);
        })
        .unwrap()
}

const PROXY_PORT: u16 = 11111;
const SERVER_PORT: u16 = 62447;
const CLIENT_PORT: u16 = 62446;

#[cfg(feature = "async")]
fn handshake_test(proxy: Proxy, send_app_data: bool) {
    let _ = simple_logger::SimpleLogger::new().init();
    let proxy = proxy.run();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let local = tokio::task::LocalSet::new();
        local.run_until(async {
            let mut set = tokio::task::JoinSet::new();
            set.spawn_local(run_handshake_async(
                SERVER_PORT,
                PROXY_PORT,
                true,
                send_app_data,
            ));
            set.spawn_local(run_handshake_async(CLIENT_PORT, PROXY_PORT, false, false));

            tokio::select! {
                _ = set.join_all() => {}
                _ = tokio::time::sleep(Duration::from_millis(4000)) => {panic!("Test timed out")}
            }
        }).await;
    });
    proxy.stop();
}

#[cfg(not(feature = "async"))]
fn handshake_test(proxy: Proxy, server_send_app_data: bool) {
    let _ = simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init();
    let proxy = proxy.run();
    let s = run_server(server_send_app_data);
    thread::sleep(Duration::from_millis(100));
    let c = run_client();

    let mut t: u64 = 5000;
    while t > 0 {
        thread::sleep(Duration::from_millis(100));
        t = t.saturating_sub(100);
        if s.is_finished() && c.is_finished() {
            break;
        }
    }
    assert!(s.is_finished(), "Server timed out");
    assert!(c.is_finished(), "Client timed out");
    s.join().unwrap();
    c.join().unwrap();
    proxy.stop();
}

const C_MSGS_DFLT: u16 = 4;
const S_MSGS_DFLT: u16 = 5;

#[test]
fn simple_handshake() {
    let mut proxy = Proxy::new();
    proxy
        .max_client_msgs(C_MSGS_DFLT)
        .max_server_msgs(S_MSGS_DFLT);
    handshake_test(proxy, false)
}

#[test]
fn reorder_encrypted_extensions() {
    let mut proxy = Proxy::new();
    proxy
        .server_action(2, Action::Store)
        .server_action(4, Action::SendStored)
        .max_client_msgs(C_MSGS_DFLT)
        .max_server_msgs(S_MSGS_DFLT);

    handshake_test(proxy, false)
}

#[test]
fn lost_client_hello_1() {
    let mut proxy = Proxy::new();
    proxy
        .client_action(0, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT + 1)
        .max_server_msgs(S_MSGS_DFLT);
    handshake_test(proxy, false)
}

#[test]
fn lost_client_hello_1_multiple_times() {
    let mut proxy = Proxy::new();
    proxy
        .client_action(0, Action::Drop)
        .client_action(1, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT + 2)
        .max_server_msgs(S_MSGS_DFLT);

    handshake_test(proxy, false)
}

#[test]
fn lost_hello_retry() {
    let mut proxy = Proxy::new();
    proxy
        .server_action(0, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT + 1)
        .max_server_msgs(S_MSGS_DFLT + 1);

    handshake_test(proxy, false)
}

#[test]
fn lost_client_hello_2() {
    let mut proxy = Proxy::new();
    proxy
        .client_action(1, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT + 1)
        .max_server_msgs(S_MSGS_DFLT);

    handshake_test(proxy, false)
}
#[test]
fn lost_server_hello() {
    let mut proxy = Proxy::new();
    proxy
        .server_action(1, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT + 1)
        .max_server_msgs(S_MSGS_DFLT + 3);
    handshake_test(proxy, false)
}

#[test]
fn lost_encrypted_extensions() {
    let mut proxy = Proxy::new();
    proxy
        .server_action(2, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT)
        .max_server_msgs(S_MSGS_DFLT + 3);
    handshake_test(proxy, false)
}

#[test]
fn lost_server_finished() {
    let mut proxy = Proxy::new();
    proxy
        .server_action(3, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT)
        .max_server_msgs(S_MSGS_DFLT + 3);
    handshake_test(proxy, false)
}

#[test]
fn lost_client_finished() {
    let mut proxy = Proxy::new();
    proxy
        .client_action(2, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT + 1)
        .max_server_msgs(S_MSGS_DFLT + 3);

    handshake_test(proxy, false)
}

#[test]
fn lost_ack() {
    let mut proxy = Proxy::new();
    proxy
        .server_action(4, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT + 1)
        .max_server_msgs(S_MSGS_DFLT + 1);

    handshake_test(proxy, false)
}

#[test]
fn implicit_ack_using_app_data() {
    let mut proxy = Proxy::new();
    proxy
        .server_action(4, Action::Drop)
        .max_client_msgs(C_MSGS_DFLT)
        .max_server_msgs(S_MSGS_DFLT + 1);
    handshake_test(proxy, true);
}

#[test]
fn encrypted_extensions_header_bitflip() {
    let mut proxy = Proxy::new();
    proxy
        .server_action(2, Action::BitFlip(0)) // Make the client think its not a EncryptedRecord
        .max_client_msgs(C_MSGS_DFLT)
        .max_server_msgs(S_MSGS_DFLT + 3);
    handshake_test(proxy, false)
}

#[test]
fn encrypted_extensions_payload_bitflip() {
    let mut proxy = Proxy::new();
    proxy
        .server_action(2, Action::BitFlip(5 * 8)) // Make the client think its not a EncryptedRecord
        .max_client_msgs(C_MSGS_DFLT)
        .max_server_msgs(S_MSGS_DFLT + 3);
    handshake_test(proxy, false)
}

#[test]
fn client_hello_1_manip_length_to_long() {
    let mut proxy = Proxy::new();
    proxy
        .client_action(
            0,
            Action::UpatePlaintextHeader(HeaderUpdate::NewLength(200)),
        )
        .max_client_msgs(C_MSGS_DFLT + 1)
        .max_server_msgs(S_MSGS_DFLT);
    handshake_test(proxy, false);
}

#[test]
fn client_hello_1_manip_length_to_short() {
    let mut proxy = Proxy::new();
    proxy
        .client_action(0, Action::UpatePlaintextHeader(HeaderUpdate::NewLength(20)))
        .max_client_msgs(C_MSGS_DFLT + 1)
        .max_server_msgs(S_MSGS_DFLT);
    handshake_test(proxy, false);
}
