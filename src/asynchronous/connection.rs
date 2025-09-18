use core::{borrow::BorrowMut, net::SocketAddr, ops::Range};

use embassy_futures::select::{Either, select};
use embedded_time::{duration, fixed_point::FixedPoint};
use log::trace;
use rand_core::CryptoRngCore;
use sha2::digest::generic_array::GenericArray;

use crate::{
    ConnectionId, DeferredAction, DtlsConnection, DtlsError, DtlsPoll, EpochState, HandshakeSlot,
    HandshakeSlotIndex, HandshakeSlotState, HandshakeState, Milliseconds, SelectNamedGroup,
    StackContext, accept_connection, close_connection, default_select_named_group,
    handshake::{ClientState, ServerState},
    open_connection,
    parsing_utility::ParseBuffer,
    record_parsing::{EncodeCiphertextRecord, RecordContentType},
    stage_alert, try_open_new_handshake, try_pass_packet_to_connection,
    try_pass_packet_to_handshake,
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
    OpenedConnection(HandshakeSlotIndex),
    AbortedHandshake(HandshakeSlotIndex),
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

    context: StackContext<'a>,

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
            context: StackContext {
                rng,
                staging_buffer,
                select_group: default_select_named_group,
                require_cookie: true,
                cookie_key: GenericArray::default(),
            },
            delay,
            clock,
            socket,
            addr,
        };
        me.context
            .rng
            .try_fill_bytes(&mut me.context.cookie_key)
            .map_err(|_| DtlsError::RngError)?;
        Ok(me)
    }

    pub fn staging_buffer(&mut self) -> &mut [u8] {
        self.context.staging_buffer
    }

    fn now_ms(&mut self) -> Result<Milliseconds, DtlsError> {
        let now_instant = self.clock.try_now().map_err(|_| DtlsError::IoError)?;
        let now = now_instant.duration_since_epoch();
        let now = duration::Milliseconds::<<Clock as embedded_time::Clock>::T>::try_from(now)
            .map_err(|_| DtlsError::IoError)?;
        let now = now.integer().into() as Milliseconds;
        Ok(now)
    }

    pub async fn read(
        &mut self,
        handshakes: &mut [HandshakeSlot<'_>],
        read_timeout: Milliseconds,
    ) -> Result<Event, DtlsError> {
        let start_ms = self.now_ms()?;
        loop {
            let now = self.now_ms()?;

            let time_elapsed = now - start_ms;
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
                        #[allow(clippy::unnecessary_cast)]
                        self.delay.delay_ms(timeout as u32),
                        self.socket.receive_into(self.context.staging_buffer),
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
                            #[allow(clippy::unnecessary_cast)]
                            self.delay.delay_ms((read_timeout - time_elapsed) as u32),
                            self.socket.receive_into(self.context.staging_buffer),
                        )
                        .await;
                        let Either::Second(received) = select else {
                            continue;
                        };
                        received
                    } else {
                        self.socket.receive_into(self.context.staging_buffer).await
                    }
                }
                DtlsPoll::FinishedHandshake(i) => return Ok(Event::OpenedConnection(i)),
                DtlsPoll::AbortedHandshake(i) => return Ok(Event::AbortedHandshake(i)),
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
        open_connection(slot, &mut self.connections, addr)
    }

    /// Accepts connections on this slot.
    /// Returns whether the slot now would accept a connection.
    pub fn accept_connection(&mut self, slot: &mut HandshakeSlot) -> bool {
        accept_connection(slot)
    }

    /// Returns whether the connection was closed successfully
    pub async fn close_connection(&mut self, connection_id: ConnectionId) -> bool {
        let addr = self
            .connections
            .get(connection_id.0)
            .and_then(|c| c.as_ref().map(|c| c.addr));
        match (
            addr,
            close_connection(
                self.context.staging_buffer,
                &mut self.connections,
                connection_id,
            ),
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
            let mut buffer = ParseBuffer::init(self.context.staging_buffer.borrow_mut());
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
        now_ms: &Milliseconds,
        handshakes: &mut [HandshakeSlot<'_>],
    ) -> Result<DtlsPoll, DtlsError> {
        let mut return_poll = DtlsPoll::Wait;
        for (handshake_index, handshake) in handshakes.iter_mut().enumerate() {
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
                                &mut self.context,
                                &mut socket,
                                handshake_index,
                                ctx,
                                c,
                                &mut handshake.rt_queue,
                                &handshake.settings,
                                conn,
                                now_ms,
                            )
                            .await
                        }
                        crate::HandshakeState::Server(s) => {
                            process_server_async(
                                &mut self.context,
                                &mut socket,
                                handshake_index,
                                ctx,
                                s,
                                &mut handshake.rt_queue,
                                conn,
                                now_ms,
                            )
                            .await
                        }
                    };
                    try_send_alert_async(
                        &poll,
                        self.context.staging_buffer,
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
                HandshakeSlotState::AcceptConnection => DtlsPoll::Wait,
                HandshakeSlotState::Empty => DtlsPoll::Wait,
                HandshakeSlotState::Finished(_) => DtlsPoll::FinishedHandshake(handshake_index),
                HandshakeSlotState::Aborted(_) => DtlsPoll::AbortedHandshake(handshake_index),
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
            self.context.staging_buffer,
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
            &mut self.context,
            handshakes,
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
        trace!("Could not match packet to handshake");
        if let Some(buf) = try_open_new_handshake(
            &mut self.context,
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
        self.context.require_cookie = require_cookie;
    }

    pub fn select_group(&mut self, select_group: SelectNamedGroup) {
        self.context.select_group = select_group
    }
}

async fn try_send_alert_async<T, Socket: embedded_nal_async::UnconnectedUdp>(
    error: &Result<T, DtlsError>,
    staging_buffer: &mut [u8],
    socket: &mut SocketAndAddr<'_, Socket>,
    epoch_states: &mut [EpochState],
    epoch: &u64,
) {
    if let Err(DtlsError::Alert(alert)) = error
        && let Ok(buf) = stage_alert(staging_buffer, epoch_states, epoch, *alert)
    {
        let _ = socket.send(buf).await;
    }
}
