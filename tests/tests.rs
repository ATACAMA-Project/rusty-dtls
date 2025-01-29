use core::panic;
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use rusty_dtls::{HandshakeSlot, HashFunction, Psk};

#[cfg(not(feature = "async"))]
use {
    rusty_dtls::{ConnectionId, DtlsPoll, DtlsStack},
    std::{cell::Cell, ops::Range, time::Instant},
};

#[cfg(feature = "async")]
use {embedded_nal_async::UdpStack, std::net::Ipv4Addr};

use log::info;

pub enum Action {
    Drop,
    Store,
    SendStored,
    Duplicate,
}

pub struct Proxy {
    packet_count: u32,
    stored: Option<(SocketAddr, Vec<u8>)>,
    client: SocketAddr,
    server: SocketAddr,
    socket: UdpSocket,
    actions: HashMap<u32, Action>,
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
            packet_count: 0,
            stored: None,
            client: SocketAddr::from(([127, 0, 0, 1], CLIENT_PORT)),
            server: SocketAddr::from(([127, 0, 0, 1], SERVER_PORT)),
            socket: UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], PROXY_PORT))).unwrap(),
            actions: HashMap::new(),
            stopper: Arc::new(Mutex::new(false)),
        }
    }

    pub fn add_action(&mut self, package_number: u32, action: Action) {
        self.actions.insert(package_number, action);
    }

    pub fn run(mut self) -> Stopper {
        let stopper = self.stopper.clone();
        let thread = thread::spawn(move || {
            let mut buffer = [0; 500];
            self.socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            while !*self.stopper.try_lock().unwrap() {
                let action = self.actions.get(&self.packet_count);
                self.packet_count += 1;

                if let Some(Action::SendStored) = action {
                    let (addr, buf) = self.stored.take().unwrap();
                    self.socket.send_to(&buf, addr).unwrap();
                    continue;
                }
                let Ok((read, addr)) = self.socket.recv_from(&mut buffer) else {
                    continue;
                };
                let recv_addr = if addr == self.client {
                    self.server
                } else {
                    self.client
                };
                println!("RECEIVED");

                match action {
                    Some(Action::Drop) => {
                        continue;
                    }
                    Some(Action::Store) => {
                        assert!(self.stored.is_none());
                        self.stored = Some((recv_addr, buffer[..read].to_vec()));
                        continue;
                    }
                    Some(Action::Duplicate) => {
                        self.socket.send_to(&buffer[..read], recv_addr).unwrap();
                    }
                    _ => {}
                }
                println!("SENT");
                self.socket.send_to(&buffer[..read], recv_addr).unwrap();
            }
        });
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

    let mut buffer = [0; 1024];
    let mut staging_buffer = [0; 256];
    let mut rand = rand::thread_rng();
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
    println!("{addr:?}");

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
        handshakes.push(HandshakeSlot::new(&psks, &mut buffer));
    } else {
        handshakes.push(HandshakeSlot::new(&psks, &mut buffer));
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
    let socket = Mutex::new(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], own_port))).unwrap());
    let mut send_to_peer = |addr: &SocketAddr, buf: &[u8]| {
        info!("[{own_port}] Send message. Size: {}", buf.len());
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

    let mut buffer = [0; 1024];
    let mut staging_buffer = [0; 200];
    let mut rand = rand::thread_rng();
    let psks = [Psk::new(&[123], &[1, 2, 3, 4, 5], HashFunction::Sha256)];
    let mut stack =
        DtlsStack::<10>::new(&mut rand, &mut staging_buffer, &mut send_to_peer).unwrap();

    let mut handshakes = Vec::new();
    if server {
        handshakes.push(HandshakeSlot::new(&psks, &mut buffer));
    } else {
        handshakes.push(HandshakeSlot::new(&psks, &mut buffer));
        assert!(stack.open_connection(
            &mut handshakes[0],
            &format!("127.0.0.1:{}", peer_port).parse().unwrap()
        ));
    }

    let start = Instant::now();
    loop {
        let poll = stack.poll(&mut handshakes, start.elapsed().as_millis() as u64);
        assert!(poll.is_ok());
        let poll = poll.unwrap();
        match poll {
            DtlsPoll::WaitTimeoutMs(ms) => {
                info!("[{own_port}] Wait {ms}");
                socket
                    .lock()
                    .unwrap()
                    .set_read_timeout(Some(Duration::from_millis(ms as u64)))
                    .unwrap();
            }
            DtlsPoll::Wait => {
                info!("[{own_port}] Wait");
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
    thread::spawn(move || {
        run_handshake(SERVER_PORT, PROXY_PORT, true, send_app_data);
    })
}

#[cfg(not(feature = "async"))]
fn run_client() -> JoinHandle<()> {
    thread::spawn(|| {
        run_handshake(CLIENT_PORT, PROXY_PORT, false, false);
    })
}

const PROXY_PORT: u16 = 11111;
const SERVER_PORT: u16 = 62447;
const CLIENT_PORT: u16 = 62446;

#[cfg(feature = "async")]
fn handshake_test(proxy: Proxy, send_app_data: bool, timeout_milis: u64) {
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
                _ = tokio::time::sleep(Duration::from_millis(timeout_milis)) => {panic!("Test timed out")}
            }
        }).await;
    });
    proxy.stop();
}

#[cfg(not(feature = "async"))]
fn handshake_test(proxy: Proxy, send_app_data: bool, timeout_milis: u64) {
    let _ = simple_logger::SimpleLogger::new()
        // .with_level(log::LevelFilter::Info)
        .init();
    let proxy = proxy.run();
    let s = run_server(send_app_data);
    thread::sleep(Duration::from_millis(100));
    let c = run_client();
    thread::sleep(Duration::from_millis(timeout_milis));
    assert!(s.is_finished());
    assert!(c.is_finished());
    s.join().unwrap();
    c.join().unwrap();
    proxy.stop();
}

#[test]
fn simple_handshake() {
    handshake_test(Proxy::new(), false, 500)
}

#[test]
fn reorder_encrypted_extensions_hello() {
    let mut proxy = Proxy::new();
    proxy.add_action(4, Action::Store);
    proxy.add_action(6, Action::SendStored);
    handshake_test(proxy, false, 1100)
}

#[test]
fn lost_client_1_hello() {
    let mut proxy = Proxy::new();
    proxy.add_action(0, Action::Drop);
    handshake_test(proxy, false, 1100)
}

#[test]
fn lost_client_1_hello_multiple_times() {
    let mut proxy = Proxy::new();
    proxy.add_action(0, Action::Drop);
    proxy.add_action(1, Action::Drop);
    handshake_test(proxy, false, 2100)
}

#[test]
fn lost_hello_retry_hello() {
    let mut proxy = Proxy::new();
    proxy.add_action(1, Action::Drop);
    handshake_test(proxy, false, 1100)
}

#[test]
fn lost_client_2_hello() {
    let mut proxy = Proxy::new();
    proxy.add_action(2, Action::Drop);
    handshake_test(proxy, false, 1100)
}

#[test]
fn lost_server_hello() {
    let mut proxy = Proxy::new();
    proxy.add_action(3, Action::Drop);
    handshake_test(proxy, false, 1100)
}

#[test]
fn lost_encrypted_extensions() {
    let mut proxy = Proxy::new();
    proxy.add_action(4, Action::Drop);
    handshake_test(proxy, false, 1100)
}

#[test]
fn lost_server_finished() {
    let mut proxy = Proxy::new();
    proxy.add_action(5, Action::Drop);
    handshake_test(proxy, false, 1100)
}

#[test]
fn lost_client_finished() {
    let mut proxy = Proxy::new();
    proxy.add_action(6, Action::Drop);
    handshake_test(proxy, false, 1100)
}

#[test]
fn lost_ack() {
    let mut proxy = Proxy::new();
    proxy.add_action(7, Action::Drop);
    handshake_test(proxy, false, 1100)
}

#[test]
fn lost_ack_2() {
    let mut proxy = Proxy::new();
    proxy.add_action(7, Action::Drop);
    handshake_test(proxy, true, 1100)
}
