use core::{borrow::BorrowMut, net::SocketAddr, ops::Range};

use log::trace;
use rand_core::CryptoRngCore;
use sha2::digest::generic_array::GenericArray;

use crate::{
    ConnectionId, DeferredAction, DtlsConnection, DtlsError, DtlsPoll, EpochState, HandshakeSlot,
    HandshakeSlotState, HandshakeState, SelectNamedGroup, StackContext, Milliseconds,
    accept_connection, close_connection,
    crypto::default_select_named_group,
    handshake::{ClientState, ServerState},
    open_connection,
    parsing_utility::ParseBuffer,
    record_parsing::{EncodeCiphertextRecord, RecordContentType},
    stage_alert, try_open_new_handshake, try_pass_packet_to_connection,
    try_pass_packet_to_handshake,
};

use super::handshake::{process_client_sync, process_server_sync};

pub struct DtlsStack<'a, const CONNECTIONS: usize> {
    connections: [Option<DtlsConnection<'a>>; CONNECTIONS],

    context: StackContext<'a>,
    send_to_peer: &'a mut dyn FnMut(&SocketAddr, &[u8]),
}

impl<'a, const CONNECTIONS: usize> DtlsStack<'a, CONNECTIONS> {
    pub fn new(
        rng: &'a mut dyn CryptoRngCore,
        staging_buffer: &'a mut [u8],
        send_to_peer: &'a mut dyn FnMut(&SocketAddr, &[u8]),
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
            send_to_peer,
        };
        me.context
            .rng
            .try_fill_bytes(&mut me.context.cookie_key)
            .map_err(|_| DtlsError::RngError)?;
        Ok(me)
    }

    pub fn poll(
        &mut self,
        handshakes: &mut [HandshakeSlot],
        now_ms: Milliseconds,
    ) -> Result<DtlsPoll, DtlsError> {
        let mut return_poll = DtlsPoll::Wait;
        for (i, handshake) in handshakes.iter_mut().enumerate() {
            let poll = match &mut handshake.state {
                HandshakeSlotState::Running {
                    state,
                    handshake: ctx,
                } => {
                    let conn = ctx.connection(&mut self.connections);
                    let mut new_state = *state;
                    let addr = conn.addr;
                    let poll = match &mut new_state {
                        HandshakeState::Client(c) => process_client_sync(
                            &mut self.context,
                            &mut |bytes| (self.send_to_peer)(&addr, bytes),
                            i,
                            ctx,
                            c,
                            &mut handshake.rt_queue,
                            &handshake.settings,
                            conn,
                            &now_ms,
                        ),
                        HandshakeState::Server(s) => process_server_sync(
                            &mut self.context,
                            &mut |bytes| (self.send_to_peer)(&addr, bytes),
                            i,
                            ctx,
                            s,
                            &mut handshake.rt_queue,
                            conn,
                            &now_ms,
                        ),
                    };
                    try_send_alert_sync(
                        &poll,
                        self.context.staging_buffer,
                        &mut |b| (self.send_to_peer)(&addr, b),
                        &mut conn.epochs,
                        &conn.current_epoch,
                    );
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
                HandshakeSlotState::Finished(_) => DtlsPoll::FinishedHandshake(i),
                HandshakeSlotState::Aborted(_) => DtlsPoll::AbortedHandshake(i),
            };
            return_poll = return_poll.merge(poll);
        }
        Ok(return_poll)
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
    pub fn close_connection(&mut self, connection_id: ConnectionId) -> bool {
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
            (Some(addr), DeferredAction::Send(buf)) => {
                (self.send_to_peer)(&addr, buf);
                true
            }
            (_, DeferredAction::None) => false,
            _ => unreachable!(),
        }
    }

    pub fn send_dtls_packet(
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
            (self.send_to_peer)(&connection.addr, buffer.as_ref());
            Ok(())
        } else {
            Err(DtlsError::UnknownConnection)
        }
    }

    pub fn staging_buffer(&mut self) -> &mut [u8] {
        self.context.staging_buffer
    }

    pub fn handle_dtls_packet(
        &mut self,
        handshakes: &mut [HandshakeSlot],
        addr: &SocketAddr,
        packet_len: usize,
        handle_app_data: &mut dyn FnMut(ConnectionId, Range<usize>, &mut Self),
    ) -> Result<(), DtlsError> {
        let mut handled = true;
        match try_pass_packet_to_connection(
            self.context.staging_buffer,
            &mut self.connections,
            addr,
            packet_len,
        )? {
            DeferredAction::Send(buf) => (self.send_to_peer)(addr, buf),
            DeferredAction::AppData(id, range) => handle_app_data(id, range, self),
            DeferredAction::None => {}
            DeferredAction::Unhandled => handled = false,
        }
        if handled {
            return Ok(());
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
            DeferredAction::Send(buf) => (self.send_to_peer)(addr, buf),
            DeferredAction::AppData(id, range) => handle_app_data(id, range, self),
            DeferredAction::None => {}
            DeferredAction::Unhandled => handled = false,
        }
        if handled {
            return Ok(());
        }
        trace!("Could not match packet to handshake");
        if let Some(buf) = try_open_new_handshake(
            &mut self.context,
            handshakes,
            &mut self.connections,
            addr,
            packet_len,
        )? {
            (self.send_to_peer)(addr, buf);
        };
        Ok(())
    }

    pub fn require_cookie(&mut self, require_cookie: bool) {
        self.context.require_cookie = require_cookie;
    }

    pub fn select_group(&mut self, select_group: SelectNamedGroup) {
        self.context.select_group = select_group
    }
}

fn try_send_alert_sync<T>(
    error: &Result<T, DtlsError>,
    staging_buffer: &mut [u8],
    send_bytes: &mut dyn FnMut(&[u8]),
    epoch_states: &mut [EpochState],
    epoch: &u64,
) {
    if let Err(DtlsError::Alert(alert)) = error
        && let Ok(buf) = stage_alert(staging_buffer, epoch_states, epoch, *alert)
    {
        send_bytes(buf);
    }
}

#[cfg(test)]
mod tests {
    use crate::{DtlsError, DtlsStack, HandshakeSlot};
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    pub fn fail_open_more_handshakes_than_connections() {
        let mut rng = rand::thread_rng();
        let mut send_to_peer = |_: &SocketAddr, _: &[u8]| {};
        let mut stack = DtlsStack::<1>::new(&mut rng, &mut [], &mut send_to_peer).unwrap();
        let mut hs = [
            HandshakeSlot::new(&[], &[], &mut []),
            HandshakeSlot::new(&[], &[], &mut []),
        ];
        let res = stack.open_connection(
            &mut hs[0],
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        );
        assert!(res);
        let res = stack.open_connection(
            &mut hs[1],
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        );
        assert!(!res);
    }

    #[test]
    pub fn closing_connections_works() {
        let mut rng = rand::thread_rng();
        let mut send_to_peer = |_: &SocketAddr, _: &[u8]| {};
        let mut b = [0; 250];
        let mut stack = DtlsStack::<1>::new(&mut rng, &mut b, &mut send_to_peer).unwrap();
        let mut hs = [HandshakeSlot::new(&[], &[], &mut [])];
        let res = stack.open_connection(
            &mut hs[0],
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        );
        assert!(res);

        hs[0].finish_handshake(stack.connections[0].as_mut().unwrap());
        assert!(hs[0].try_take_connection_id().is_some());

        let res = stack.close_connection(crate::ConnectionId(0));
        assert!(res);
        let res = stack.open_connection(
            &mut hs[0],
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        );
        assert!(res);
    }

    #[test]
    pub fn try_close_non_open_connection() {
        let mut rng = rand::thread_rng();
        let mut send_to_peer = |_: &SocketAddr, _: &[u8]| {};
        let mut stack = DtlsStack::<1>::new(&mut rng, &mut [], &mut send_to_peer).unwrap();
        let mut hs = [HandshakeSlot::new(&[], &[], &mut [])];
        let res = stack.open_connection(
            &mut hs[0],
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        );
        assert!(res);
        let res = stack.close_connection(crate::ConnectionId(0));
        assert!(!res);
    }

    #[test]
    pub fn overflow_stage_buffer() {
        let mut rng = rand::thread_rng();
        let mut send_to_peer = |_: &SocketAddr, _: &[u8]| {};
        let mut stage_buffer = [0u8; 250];
        let mut stack =
            DtlsStack::<1>::new(&mut rng, &mut stage_buffer, &mut send_to_peer).unwrap();
        let mut hs = [HandshakeSlot::new(&[], &[], &mut [])];
        let res = stack.open_connection(
            &mut hs[0],
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        );
        assert!(res);
        hs[0].finish_handshake(stack.connections[0].as_mut().unwrap());
        let cid = hs[0].try_take_connection_id().unwrap();
        let data = [1u8; 249];

        let e = stack.send_dtls_packet(cid, &data);
        assert!(matches!(e, Err(DtlsError::OutOfMemory)));
    }
}
