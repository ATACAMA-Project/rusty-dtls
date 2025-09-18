use core::panic;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        self, Arc, Mutex,
        mpsc::{Receiver, Sender, channel},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use rusty_dtls::{AlertDescription, NamedGroup};

use rand::{RngCore, SeedableRng};
use rusty_dtls::{HandshakeSlot, HashFunction, Psk};

#[cfg(not(feature = "async"))]
use {
    rusty_dtls::{ConnectionId, DtlsPoll, DtlsStack},
    std::{cell::Cell, ops::Range, time::Instant},
};

#[cfg(feature = "async")]
use {std::net::Ipv4Addr, tokio::time::interval};

use log::{debug, info};

/// CH + Cookie + management info: (1B Flag, 8B Length)
const HANDSHAKE_BUFFER_SIZE: usize = 290 + 64 + 2 * 9;
const STAGING_BUFFER_SIZE: usize = 291;

const SERVER_PORT: u16 = 62447;
const CLIENT_PORT: u16 = 62446;

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum HeaderUpdate {
    NewLength(u16),
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum Action {
    Drop,
    BitFlip(usize),
    UpdatePlaintextHeader(HeaderUpdate),
    Truncate(usize),
    Store,
    SendStored,
    Duplicate,
}

impl Action {
    fn run(
        &self,
        proxy: &mut Proxy,
        send_addr: &SocketAddr,
        recv_addr: &SocketAddr,
        recv_tx: &mut Sender<Packet>,
        recv_buf: &mut [u8],
        msg_len: &mut usize,
    ) -> bool {
        match self {
            Action::SendStored => panic!(),
            Action::Truncate(size) => {
                *msg_len = *size;
                false
            }
            Action::BitFlip(pos) => {
                debug!(
                    "Flip bit {} in {send_addr:?} => {recv_addr:?} {msg_len}",
                    pos
                );
                recv_buf[pos / 8] ^= 1 << (7 - (pos % 8));
                false
            }
            Action::UpdatePlaintextHeader(HeaderUpdate::NewLength(len)) => {
                debug!("Update length to {} in {send_addr:?} => {recv_addr:?}", len);
                recv_buf[11..=12].copy_from_slice(&len.to_be_bytes());
                false
            }
            Action::Drop => {
                debug!("Drop {send_addr:?} => {recv_addr:?} {msg_len}");
                true
            }
            Action::Store => {
                debug!("Store {send_addr:?} => {recv_addr:?} {msg_len}");
                if send_addr == &proxy.client.addr {
                    assert!(proxy.client.stored.is_none());
                    proxy.client.stored = Some((*recv_addr, recv_buf[..*msg_len].to_vec()));
                } else {
                    assert!(proxy.server.stored.is_none());
                    proxy.server.stored = Some((*recv_addr, recv_buf[..*msg_len].to_vec()));
                }
                true
            }
            Action::Duplicate => {
                debug!("Duplicate {send_addr:?} => {recv_addr:?} {msg_len}");
                recv_tx.send((*send_addr, recv_buf.to_vec())).unwrap();
                false
            }
        }
    }
}

pub struct EndpointCfg {
    action_index: u32,
    stored: Option<Packet>,
    addr: SocketAddr,
    actions: HashMap<u32, Action>,
    allowed_msgs: i32,
    hs_cfg: HandshakeCfg,
}

#[derive(Clone)]
pub struct HandshakeCfg {
    expected_abort: Option<AlertDescription>,
    #[allow(unused)]
    psk_exch_modes: (bool, bool),
    offered_key_shares: Vec<NamedGroup>,
    psks: Arc<Vec<Psk<'static>>>,
}

pub struct Proxy {
    client: EndpointCfg,
    server: EndpointCfg,
    stopper: Arc<Mutex<bool>>,

    require_cookie: bool,
    server_send_app_data: bool,
}

impl Default for Proxy {
    fn default() -> Self {
        Self::new()
    }
}

type Packet = (SocketAddr, Vec<u8>);

#[allow(dead_code)]
impl Proxy {
    pub fn new() -> Self {
        Self {
            client: EndpointCfg {
                action_index: 0,
                stored: None,
                addr: SocketAddr::from(([127, 0, 0, 1], CLIENT_PORT)),
                actions: HashMap::new(),
                allowed_msgs: i32::MAX,
                hs_cfg: HandshakeCfg {
                    expected_abort: None,
                    psk_exch_modes: (true, false),
                    offered_key_shares: Vec::new(),
                    psks: Arc::new(vec![Psk::new(
                        &[123],
                        &[1, 2, 3, 4, 5],
                        HashFunction::Sha256,
                    )]),
                },
            },
            server: EndpointCfg {
                action_index: 0,
                stored: None,
                addr: SocketAddr::from(([127, 0, 0, 1], SERVER_PORT)),
                actions: HashMap::new(),
                allowed_msgs: i32::MAX,
                hs_cfg: HandshakeCfg {
                    expected_abort: None,
                    psk_exch_modes: (true, false),
                    offered_key_shares: Vec::new(),
                    psks: Arc::new(vec![Psk::new(
                        &[123],
                        &[1, 2, 3, 4, 5],
                        HashFunction::Sha256,
                    )]),
                },
            },
            stopper: Arc::new(Mutex::new(false)),

            require_cookie: true,
            server_send_app_data: false,
        }
    }
    pub fn client_msgs(&mut self, msgs: u16) -> &mut Self {
        self.client.allowed_msgs = msgs as i32;
        self
    }

    pub fn client_action(&mut self, package_number: u32, action: Action) -> &mut Self {
        self.client.actions.insert(package_number, action);
        self
    }

    pub fn server_msgs(&mut self, msgs: u16) -> &mut Self {
        self.server.allowed_msgs = msgs as i32;
        self
    }

    pub fn server_action(&mut self, package_number: u32, action: Action) -> &mut Self {
        self.server.actions.insert(package_number, action);
        self
    }

    pub fn server_require_cookie(&mut self, require_cookie: bool) -> &mut Self {
        self.require_cookie = require_cookie;
        self
    }

    pub fn server_send_app_data(&mut self, send_app_data: bool) -> &mut Self {
        self.server_send_app_data = send_app_data;
        self
    }

    pub fn client_expect_abort(&mut self, reason: AlertDescription) -> &mut Self {
        self.client.hs_cfg.expected_abort = Some(reason);
        self
    }

    pub fn client_psks(&mut self, psks: &[Psk<'static>]) -> &mut Self {
        self.client.hs_cfg.psks = Arc::new(psks.to_vec());
        self
    }

    pub fn server_psks(&mut self, psks: &[Psk<'static>]) -> &mut Self {
        self.server.hs_cfg.psks = Arc::new(psks.to_vec());
        self
    }

    #[cfg(feature = "_dhe")]
    pub fn client_psk_exch_modes(&mut self, psk_exch: bool, psk_dhe_exch: bool) -> &mut Self {
        self.client.hs_cfg.psk_exch_modes = (psk_exch, psk_dhe_exch);
        self
    }

    #[cfg(feature = "_dhe")]
    pub fn client_offer_key_shares(&mut self, shares: &[NamedGroup]) -> &mut Self {
        self.client.hs_cfg.offered_key_shares = shares.to_vec();
        self
    }

    #[cfg(feature = "_dhe")]
    pub fn server_psk_exch_modes(&mut self, psk_exch: bool, psk_dhe_exch: bool) -> &mut Self {
        self.server.hs_cfg.psk_exch_modes = (psk_exch, psk_dhe_exch);
        self
    }

    fn stopped(&self) -> bool {
        let res = self.stopper.try_lock();
        match res {
            Ok(res) => *res,
            Err(sync::TryLockError::WouldBlock) => false,
            Err(sync::TryLockError::Poisoned(e)) => panic!("{:?}", e),
        }
    }

    pub fn run(
        mut self,
        mut s_tx: Sender<Packet>,
        mut c_tx: Sender<Packet>,
        rx: Receiver<Packet>,
    ) -> Stopper {
        let stopper = self.stopper.clone();
        let thread = thread::Builder::new()
            .name("Proxy".to_string())
            .spawn(move || {
                while !self.stopped() {
                    assert!(
                        self.client.allowed_msgs >= 0,
                        "Client sent more messages than allowed"
                    );
                    assert!(
                        self.server.allowed_msgs >= 0,
                        "Server sent more messages than allowed"
                    );

                    let client_action = self.client.actions.get(&self.client.action_index).copied();
                    let server_action = self.server.actions.get(&self.server.action_index).copied();

                    if let Some(Action::SendStored) = client_action {
                        let (addr, buf) = self.client.stored.take().unwrap();
                        debug!(
                            "Send stored {:?} => {addr:?} {}",
                            &self.client.addr,
                            buf.len()
                        );
                        s_tx.send((self.client.addr, buf.to_vec())).unwrap();
                        self.client.action_index += 1;
                        continue;
                    }
                    if let Some(Action::SendStored) = server_action {
                        let (addr, buf) = self.server.stored.take().unwrap();
                        debug!(
                            "Send stored {:?} => {addr:?} {}",
                            &self.server.addr,
                            buf.len(),
                        );
                        c_tx.send((self.server.addr, buf.to_vec())).unwrap();
                        self.server.action_index += 1;
                        continue;
                    }

                    let Ok((recv_addr, mut buf)) = rx.recv_timeout(Duration::from_millis(500)) else {
                        continue;
                    };

                    if recv_addr == self.server.addr {
                        let send_addr = self.client.addr;
                        self.client.allowed_msgs -= 1;
                        self.client.action_index += 1;
                        let mut read = buf.len();
                        if let Some(action) = client_action
                            && action.run(
                                &mut self,
                                &send_addr,
                                &recv_addr,
                                &mut s_tx,
                                buf.as_mut(),
                                &mut read,
                            )
                        {
                            continue;
                        }
                        debug!("Forwarding {:?} => {recv_addr:?} {read}", self.client.addr);
                        s_tx.send((self.client.addr, buf[..read].to_vec())).unwrap()
                    }
                    if recv_addr == self.client.addr {
                        let send_addr = self.server.addr;
                        self.server.allowed_msgs -= 1;
                        self.server.action_index += 1;
                        let mut read = buf.len();
                        if let Some(action) = server_action
                            && action.run(
                                &mut self,
                                &send_addr,
                                &recv_addr,
                                &mut c_tx,
                                buf.as_mut(),
                                &mut read,
                            )
                        {
                            continue;
                        }
                        debug!("Forwarding {:?} => {recv_addr:?} {read}", self.server.addr);
                        c_tx.send((self.server.addr, buf[..read].to_vec())).unwrap()
                    }
                }
                assert_eq!(
                    self.client.allowed_msgs, 0,
                    "Client sent wrong count of msgs"
                );
                assert_eq!(
                    self.server.allowed_msgs, 0,
                    "Server sent wrong count of msgs"
                );

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
struct ChannelSocket {
    tx: Sender<Packet>,
    rx: Receiver<Packet>,
}

#[cfg(feature = "async")]
impl embedded_nal_async::UnconnectedUdp for ChannelSocket {
    type Error = std::convert::Infallible;

    async fn send(
        &mut self,
        _local: SocketAddr,
        remote: SocketAddr,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.tx.send((remote, data.to_vec())).unwrap();
        Ok(())
    }

    async fn receive_into(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr, SocketAddr), Self::Error> {
        let mut i = interval(Duration::from_millis(1));
        loop {
            i.tick().await;
            let res = self.rx.try_recv();
            match res {
                Ok((addr, buf)) => {
                    let l = buf.len().min(buffer.len());
                    buffer[..l].copy_from_slice(&buf[..l]);
                    return Ok((l, addr, addr));
                }
                Err(sync::mpsc::TryRecvError::Empty) => {}
                Err(e) => panic!("{:?}", e),
            }
        }
    }
}

struct HandshakeResult {
        abort_reason: Option<AlertDescription>,
}

impl HandshakeResult {
    fn empty() -> HandshakeResult {
        HandshakeResult {abort_reason: None}
    }

    fn abort(reason: AlertDescription) -> HandshakeResult {
        HandshakeResult { abort_reason: Some(reason)}
    }
}

#[cfg(feature = "async")]
async fn run_handshake_async(
    own_port: u16,
    peer_port: u16,
    socket: ChannelSocket,
    hs_cfg: HandshakeCfg,
    server: bool,
    server_send_app_data: bool,
    server_require_cookie: bool,
) -> HandshakeResult {
    use rusty_dtls::DtlsStackAsync;

    let mut buffer = [0; HANDSHAKE_BUFFER_SIZE];
    let mut staging_buffer = [0; STAGING_BUFFER_SIZE];

    let seed = rand::thread_rng().next_u64();
    info!("[{own_port}] Using seed {seed}");
    let mut rand = rand::rngs::StdRng::seed_from_u64(seed);

    let delay = linux_embedded_hal::Delay;
    let clock = std_embedded_time::StandardClock::default();

    let addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), own_port);
    let mut stack = DtlsStackAsync::<'_, _, _, _, 10>::new(
        &mut rand,
        &mut staging_buffer,
        delay,
        clock,
        socket,
        addr,
    )
    .unwrap();
    stack.require_cookie(server_require_cookie);
    let mut handshakes = Vec::new();
    if server {
        handshakes.push(HandshakeSlot::new(
            &hs_cfg.psks,
            &hs_cfg.offered_key_shares,
            &mut buffer,
        ));
        assert!(stack.accept_connection(&mut handshakes[0],));
    } else {
        handshakes.push(HandshakeSlot::new(
            &hs_cfg.psks,
            &hs_cfg.offered_key_shares,
            &mut buffer,
        ));
        assert!(stack.open_connection(
            &mut handshakes[0],
            &format!("127.0.0.1:{}", peer_port).parse().unwrap()
        ));
    }
    #[cfg(feature = "_dhe")]
    {
        handshakes[0].set_psk_exchange_modes(hs_cfg.psk_exch_modes.0, hs_cfg.psk_exch_modes.1);
    }

    loop {
        let e = stack.read(&mut handshakes, 5000).await;
        match e.unwrap() {
            rusty_dtls::Event::AppData(_, range) => {
                if &stack.staging_buffer()[range] == "Client App Data".as_bytes() {
                    return HandshakeResult::empty();
                }
            }
            rusty_dtls::Event::OpenedConnection(i) => {
                let id = handshakes[i].try_take_connection_id().unwrap();
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
                    return HandshakeResult::empty();
                }
            }
            rusty_dtls::Event::AbortedHandshake(i) => {
                let reason = handshakes[i].try_take_abort_reason().unwrap();
                info!("[{own_port}] Handshake aborted: {:?}", reason);
                return HandshakeResult::abort(reason);
            }
            _ => {}
        };
    }
}

#[cfg(feature = "async")]
pub fn handshake_test(proxy: Proxy) {
    use log::LevelFilter;

    let _ = simple_logger::SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .init();
    let (xp_tx, xp_rx) = channel::<Packet>();
    let (ps_tx, ps_rx) = channel::<Packet>();
    let (pc_tx, pc_rx) = channel::<Packet>();

    let require_cookie = proxy.require_cookie;
    let server_send_app_data = proxy.server_send_app_data;
    let server_hs_cfg = proxy.server.hs_cfg.clone();
    let client_hs_cfg = proxy.client.hs_cfg.clone();

    let proxy = proxy.run(ps_tx, pc_tx, xp_rx);
    thread::sleep(Duration::from_millis(100));

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let local = tokio::task::LocalSet::new();
        local.run_until(async {
            let mut set = tokio::task::JoinSet::new();
            let server_abort_handle = set.spawn_local(run_handshake_async(
                SERVER_PORT,
                CLIENT_PORT,
                ChannelSocket { tx: xp_tx.clone(), rx: ps_rx },
                server_hs_cfg.clone(),
                true,
                server_send_app_data,
                require_cookie
            ));
            set.spawn_local(run_handshake_async(CLIENT_PORT, SERVER_PORT,
                ChannelSocket { tx: xp_tx, rx: pc_rx },client_hs_cfg.clone(), false, false, false));
            tokio::select! {
                _ = async {
                    while let Some(res) = set.join_next().await {
                        match res {
                            Ok(result) =>
                            if let HandshakeResult {abort_reason: Some(reason)} = result{
                                assert_eq!(Some(reason),client_hs_cfg.expected_abort);
                                server_abort_handle.abort();
                            },
                            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
                            Err(_) => {}, // canceled
                        }
                    }
                    
                } => {}
                _ = tokio::time::sleep(Duration::from_millis(4000)) => {
                        panic!("Test timed out")
                }
            }
        }).await;
    });
    proxy.stop();
}

#[cfg(not(feature = "async"))]
fn run_handshake(
    tx: Sender<Packet>,
    rx: Receiver<Packet>,
    own_port: u16,
    peer_port: u16,
    server: bool,
    server_send_app_data: bool,
    require_cookie: bool,
    hs_cfg: HandshakeCfg
) -> HandshakeResult {
    use log::error;

    let mut send_to_peer = |addr: &SocketAddr, buf: &[u8]| {
        debug!("[{own_port}] Send message. Size: {}", buf.len());
        tx.send((*addr, buf.to_vec())).unwrap();
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

    let mut buffer = [0; HANDSHAKE_BUFFER_SIZE];
    let mut staging_buffer = [0; STAGING_BUFFER_SIZE];

    let seed = rand::thread_rng().next_u64();
    info!("[{own_port}] Using seed {seed}");
    let mut rand = rand::rngs::StdRng::seed_from_u64(seed);

    let mut stack =
        DtlsStack::<10>::new(&mut rand, &mut staging_buffer, &mut send_to_peer).unwrap();
    stack.require_cookie(require_cookie);

    let mut handshakes = Vec::new();
    if server {
        handshakes.push(HandshakeSlot::new(&hs_cfg.psks, &hs_cfg.offered_key_shares, &mut buffer));
        assert!(stack.accept_connection(&mut handshakes[0],));
    } else {
        handshakes.push(HandshakeSlot::new(&hs_cfg.psks, &hs_cfg.offered_key_shares, &mut buffer));
        assert!(stack.open_connection(
            &mut handshakes[0],
            &format!("127.0.0.1:{}", peer_port).parse().unwrap()
        ));
    }

    #[cfg(feature = "_dhe")]
    handshakes[0].set_psk_exchange_modes(hs_cfg.psk_exch_modes.0, hs_cfg.psk_exch_modes.1);

    let start = Instant::now();
    loop {
        use rusty_dtls::Milliseconds;

        let poll = stack.poll(&mut handshakes, start.elapsed().as_millis() as Milliseconds);
        if poll.is_err() {
            error!("[{own_port}] PollErr: {poll:?}");
        }
        assert!(poll.is_ok());
        let poll = poll.unwrap();
        let mut timeout = None;
        match poll {
            DtlsPoll::WaitTimeoutMs(ms) => {
                // debug!("[{own_port}] Wait {ms}");
                timeout = Some(Duration::from_millis(ms as u64 / 2));
            }
            DtlsPoll::Wait => {
                debug!("[{own_port}] Wait");
            }
            DtlsPoll::FinishedHandshake(i) => {
                let hs = &mut handshakes[i];
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
                    return HandshakeResult::empty();
                }
            }
            DtlsPoll::AbortedHandshake(i) => {
                let hs = &mut handshakes[i];
                let Some(reason) = hs.try_take_abort_reason() else {
                    continue;
                };
                info!("[{own_port}] Aborted handshake: {:?}", reason);
                return HandshakeResult::abort(reason);
            }
        }
        let packet = if let Some(timeout) = timeout {
            rx.recv_timeout(timeout).ok()
        } else if let Ok(v) = rx.recv() {
            Some(v)
        } else {
            return HandshakeResult::empty()
        };
        let Some((addr, buf)) = packet else {
            continue;
        };
        let l = stack.staging_buffer().len().min(buf.len());
        stack.staging_buffer()[..l].clone_from_slice(&buf[..l]);
        stack
            .handle_dtls_packet(&mut handshakes, &addr, l, &mut handle_app_data)
            .unwrap();
        if got_app_data.get() {
            return HandshakeResult::empty();
        }
    }
}

#[cfg(not(feature = "async"))]
fn run_server(
    send_app_data: bool,
    require_cookie: bool,
    tx: Sender<Packet>,
    rx: Receiver<Packet>,
    hs_cfg: HandshakeCfg,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("Server".to_string())
        .spawn(move || {
            run_handshake(tx, rx, SERVER_PORT, CLIENT_PORT, true, send_app_data,require_cookie,hs_cfg);
        })
        .unwrap()
}

#[cfg(not(feature = "async"))]
fn run_client(tx: Sender<Packet>, rx: Receiver<Packet>,
    hs_cfg: HandshakeCfg,
) -> JoinHandle<HandshakeResult> {
    thread::Builder::new()
        .name("Client".to_string())
        .spawn(move || {
            run_handshake(tx, rx, CLIENT_PORT, SERVER_PORT, false, false,false,hs_cfg)
        })
        .unwrap()
}

#[cfg(not(feature = "async"))]
pub fn handshake_test(proxy: Proxy) {
    let _ = simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init();
    let (xp_tx, xp_rx) = channel::<Packet>();
    let (ps_tx, ps_rx) = channel::<Packet>();
    let (pc_tx, pc_rx) = channel::<Packet>();

    let send_data = proxy.server_send_app_data;
    let require_cookie = proxy.require_cookie;
    let server_hs_cfg = proxy.server.hs_cfg.clone();
    let client_hs_cfg = proxy.client.hs_cfg.clone();

    let proxy_stopper = proxy.run(ps_tx, pc_tx, xp_rx);
    let s = run_server(send_data, require_cookie, xp_tx.clone(), ps_rx,server_hs_cfg);
    thread::sleep(Duration::from_millis(100));
    let c = run_client(xp_tx, pc_rx, client_hs_cfg.clone());

    let expect_abort = client_hs_cfg.expected_abort.is_some();
    let mut t: u64 = 5000;
    while t > 0 {
        thread::sleep(Duration::from_millis(10));
        t = t.saturating_sub(10);
        if s.is_finished() && c.is_finished() {
            break;
        }
        if c.is_finished() && expect_abort {
            break
        }
    }
    assert!(s.is_finished() || expect_abort, "Server timed out");
    assert!(c.is_finished(), "Client timed out");

    let result = c.join().unwrap();
    assert_eq!(result.abort_reason,client_hs_cfg.expected_abort);

    proxy_stopper.stop();

    assert!(s.is_finished() , "Server did not stop!");
    s.join().unwrap();
}

// CH1, CH2, FIN, APPDATA
pub const C_MSGS_DFLT: u16 = 4;
// HRT, SH, ENC, FIN, APPDATA
pub const S_MSGS_DFLT: u16 = 5;
