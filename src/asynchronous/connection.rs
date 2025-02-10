use core::{borrow::BorrowMut, net::SocketAddr, ops::Range};

use embassy_futures::select::{select, Either};
use embedded_time::{duration::Milliseconds, fixed_point::FixedPoint};
use log::trace;
use rand_core::CryptoRngCore;
use sha2::{
    digest::{generic_array::GenericArray, OutputSizeUser},
    Sha256,
};

use crate::{
    close_connection,
    handshake::{ClientState, ServerState},
    open_connection,
    parsing_utility::ParseBuffer,
    record_parsing::{EncodeCiphertextRecord, RecordContentType},
    stage_alert, try_open_new_handshake, try_pass_packet_to_connection,
    try_pass_packet_to_handshake, ConnectionId, DeferredAction, DtlsConnection, DtlsError,
    DtlsPoll, EpochState, HandshakeSlot, HandshakeSlotState, HandshakeState, TimeStampMs,
};

use super::handshake::{process_client_async, process_server_async};

pub(crate) struct SocketAndAddr<'a, Socket: embedded_nal_async::UnconnectedUdp> {
    pub(crate) socket: &'a mut Socket,
    pub(crate) local: &'a SocketAddr,
    pub(crate) remote: &'a SocketAddr,
}

impl<Socket: embedded_nal_async::UnconnectedUdp> SocketAndAddr<'_, Socket> {
    pub async fn send(&mut self, data: &[u8]) -> Result<(), DtlsError> {
        self.socket
            .send(*self.local, *self.remote, data)
            .await
            .map_err(|_| DtlsError::IoError)
    }
}

pub enum Event {
    AppData(ConnectionId, Range<usize>),
    OpenedConnection,
    Timeout,
    Exit,
}

pub struct DtlsStackAsync<
    'a,
    Delay: embedded_hal_async::delay::DelayNs,
    Clock: embedded_time::Clock,
    Socket: embedded_nal_async::UnconnectedUdp,
    const CONNECTIONS: usize,
> {
    connections: [Option<DtlsConnection<'a>>; CONNECTIONS],

    rng: &'a mut dyn rand_core::CryptoRngCore,
    staging_buffer: &'a mut [u8],

    require_cookie: bool,
    // In any case the minimal recommended length for K is L bytes (as the hash output
    // length) RFC 2104
    cookie_key: GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,

    delay: Delay,
    clock: Clock,
    socket: Socket,
    addr: SocketAddr,
}

impl<
        'a,
        Delay: embedded_hal_async::delay::DelayNs,
        Clock: embedded_time::Clock,
        Socket: embedded_nal_async::UnconnectedUdp,
        const CONNECTIONS: usize,
    > DtlsStackAsync<'a, Delay, Clock, Socket, CONNECTIONS>
where
    <Clock as embedded_time::Clock>::T: Into<u64>,
{
    pub fn new(
        rng: &'a mut dyn CryptoRngCore,
        staging_buffer: &'a mut [u8],
        delay: Delay,
        clock: Clock,
        socket: Socket,
        addr: SocketAddr,
    ) -> Result<Self, DtlsError> {
        let mut me = Self {
            connections: [const { None }; CONNECTIONS],
            rng,
            staging_buffer,
            cookie_key: GenericArray::default(),
            require_cookie: true,
            delay,
            clock,
            socket,
            addr,
        };
        me.rng
            .try_fill_bytes(&mut me.cookie_key)
            .map_err(|_| DtlsError::RngError)?;
        Ok(me)
    }

    pub fn staging_buffer(&mut self) -> &mut [u8] {
        self.staging_buffer
    }

    fn now_ms(&mut self) -> Result<u64, DtlsError> {
        let now_instant = self.clock.try_now().map_err(|_| DtlsError::IoError)?;
        let now = now_instant.duration_since_epoch();
        let now = Milliseconds::<<Clock as embedded_time::Clock>::T>::try_from(now)
            .map_err(|_| DtlsError::IoError)?;
        let now: u64 = now.integer().into();
        Ok(now)
    }

    pub async fn read(
        &mut self,
        handshakes: &mut [HandshakeSlot<'_>],
        read_timeout: u32,
    ) -> Result<Event, DtlsError> {
        let start_ms = self.now_ms()?;
        loop {
            let now = self.now_ms()?;

            let time_elapsed = (now - start_ms) as u32;
            if read_timeout > 0 && time_elapsed > read_timeout {
                return Ok(Event::Timeout);
            }

            let poll = self.poll_async(&now, handshakes).await?;
            let received = match poll {
                DtlsPoll::WaitTimeoutMs(timeout) => {
                    let timeout = if read_timeout > 0 {
                        timeout.min(read_timeout - time_elapsed)
                    } else {
                        timeout
                    };
                    let select = embassy_futures::select::select(
                        self.delay.delay_ms(timeout),
                        self.socket.receive_into(self.staging_buffer),
                    )
                    .await;
                    let Either::Second(received) = select else {
                        continue;
                    };
                    received
                }
                DtlsPoll::Wait => {
                    if read_timeout > 0 {
                        let select = select(
                            self.delay.delay_ms(read_timeout - time_elapsed),
                            self.socket.receive_into(self.staging_buffer),
                        )
                        .await;
                        let Either::Second(received) = select else {
                            continue;
                        };
                        received
                    } else {
                        self.socket.receive_into(self.staging_buffer).await
                    }
                }
                DtlsPoll::FinishedHandshake => return Ok(Event::OpenedConnection),
            };
            let (read, _, remote) = received.map_err(|_| DtlsError::IoError)?;
            let data = self.handle_dtls_packet(handshakes, &remote, read).await?;
            let Some((id, range)) = data else { continue };
            return Ok(Event::AppData(id, range));
        }
    }

    /// Starts a new handshake.
    /// Returns whether the handshake was correctly started.
    pub fn open_connection(&mut self, slot: &mut HandshakeSlot, addr: &SocketAddr) -> bool {
        open_connection(&mut self.connections, slot, addr)
    }

    /// Returns whether the connection was closed successfully
    pub async fn close_connection(&mut self, connection_id: ConnectionId) -> bool {
        let addr = self
            .connections
            .get(connection_id.0)
            .and_then(|c| c.as_ref().map(|c| c.addr));
        match (
            addr,
            close_connection(connection_id, self.staging_buffer, &mut self.connections),
        ) {
            (Some(peer_addr), DeferredAction::Send(buf)) => {
                let _ = self.socket.send(self.addr, peer_addr, buf).await;
                true
            }
            (_, DeferredAction::None) => false,
            _ => unreachable!(),
        }
    }

    pub async fn send_dtls_packet(
        &mut self,
        connection_id: ConnectionId,
        packet: &[u8],
    ) -> Result<(), DtlsError> {
        if let Some(connection) = &mut self.connections[connection_id.0] {
            let mut buffer = ParseBuffer::init(self.staging_buffer.borrow_mut());
            let epoch_index = connection.current_epoch as usize & 3;
            let mut record = EncodeCiphertextRecord::new(
                &mut buffer,
                &connection.epochs[epoch_index],
                &connection.current_epoch,
            )?;
            record.payload_buffer().write_slice_checked(packet)?;
            record.finish(
                &mut connection.epochs[epoch_index],
                RecordContentType::ApplicationData,
            )?;
            self.socket
                .send(self.addr, connection.addr, buffer.as_ref())
                .await
                .map_err(|_| DtlsError::IoError)
        } else {
            Err(DtlsError::UnknownConnection)
        }
    }

    async fn poll_async(
        &mut self,
        now_ms: &TimeStampMs,
        handshakes: &mut [HandshakeSlot<'_>],
    ) -> Result<DtlsPoll, DtlsError> {
        let mut return_poll = DtlsPoll::Wait;
        for handshake in handshakes {
            let poll = match &mut handshake.state {
                HandshakeSlotState::Running {
                    state,
                    handshake: ctx,
                } => {
                    let conn = ctx.connection(&mut self.connections);
                    let mut new_state = *state;
                    let addr = conn.addr;
                    let mut socket = SocketAndAddr {
                        socket: &mut self.socket,
                        local: &self.addr,
                        remote: &addr,
                    };
                    let poll = match &mut new_state {
                        HandshakeState::Client(c) => {
                            process_client_async(
                                c,
                                now_ms,
                                ctx,
                                &mut handshake.net_queue,
                                conn,
                                self.rng,
                                self.staging_buffer,
                                &mut socket,
                            )
                            .await
                        }
                        crate::HandshakeState::Server(s) => {
                            process_server_async(
                                s,
                                now_ms,
                                ctx,
                                &mut handshake.net_queue,
                                conn,
                                self.rng,
                                self.staging_buffer,
                                &mut socket,
                            )
                            .await
                        }
                    };
                    try_send_alert_async(
                        &poll,
                        self.staging_buffer,
                        &mut socket,
                        &mut conn.epochs,
                        &conn.current_epoch,
                    )
                    .await;
                    let poll = poll?;
                    *state = new_state;
                    if matches!(
                        state,
                        HandshakeState::Client(ClientState::FinishedHandshake)
                            | HandshakeState::Server(ServerState::FinishedHandshake)
                    ) {
                        handshake.finish_handshake(conn);
                    }
                    poll
                }
                HandshakeSlotState::Empty => DtlsPoll::Wait,
                HandshakeSlotState::Finished(_) => DtlsPoll::FinishedHandshake,
            };
            return_poll = return_poll.merge(poll);
        }
        Ok(return_poll)
    }

    async fn handle_dtls_packet(
        &mut self,
        handshakes: &mut [HandshakeSlot<'_>],
        addr: &SocketAddr,
        packet_len: usize,
    ) -> Result<Option<(ConnectionId, Range<usize>)>, DtlsError> {
        let mut socket = SocketAndAddr {
            socket: &mut self.socket,
            local: &self.addr,
            remote: addr,
        };
        let mut handled = true;
        match try_pass_packet_to_connection(
            self.staging_buffer,
            &mut self.connections,
            addr,
            packet_len,
        )? {
            DeferredAction::Send(buf) => socket.send(buf).await?,
            DeferredAction::AppData(id, range) => return Ok(Some((id, range))),
            DeferredAction::None => {}
            DeferredAction::Unhandled => handled = false,
        }
        if handled {
            return Ok(None);
        }
        handled = true;
        trace!("Could not match packet to connection");
        match try_pass_packet_to_handshake(
            self.staging_buffer,
            &mut self.connections,
            handshakes,
            addr,
            packet_len,
        )? {
            DeferredAction::Send(buf) => socket.send(buf).await?,
            DeferredAction::AppData(id, range) => return Ok(Some((id, range))),
            DeferredAction::None => {}
            DeferredAction::Unhandled => handled = false,
        }
        if handled {
            return Ok(None);
        }
        trace!("Could not match packet to handshake");
        if let Some(buf) = try_open_new_handshake(
            self.staging_buffer,
            self.require_cookie,
            &self.cookie_key,
            handshakes,
            &mut self.connections,
            addr,
            packet_len,
        )? {
            socket.send(buf).await?;
        };
        Ok(None)
    }

    pub fn require_cookie(&mut self, require_cookie: bool) {
        self.require_cookie = require_cookie;
    }
}

async fn try_send_alert_async<T, Socket: embedded_nal_async::UnconnectedUdp>(
    error: &Result<T, DtlsError>,
    staging_buffer: &mut [u8],
    socket: &mut SocketAndAddr<'_, Socket>,
    epoch_states: &mut [EpochState],
    epoch: &u64,
) {
    if let Err(DtlsError::Alert(alert)) = error {
        if let Ok(buf) = stage_alert(staging_buffer, epoch_states, epoch, *alert) {
            let _ = socket.send(buf).await;
        }
    }
}
