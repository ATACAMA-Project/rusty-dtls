use log::trace;

use crate::{
    handshake::{process_client, process_server, ClientState, HandshakeContext, ServerState},
    DtlsConnection, DtlsError, DtlsPoll, RecordQueue,
};

pub fn process_client_sync(
    state: &mut ClientState,
    now_ms: &u64,
    ctx: &mut HandshakeContext,
    record_queue: &mut RecordQueue<'_>,
    conn: &mut DtlsConnection,
    rng: &mut dyn rand_core::CryptoRngCore,
    staging_buffer: &mut [u8],
    send_bytes: &mut dyn FnMut(&[u8]),
) -> Result<DtlsPoll, DtlsError> {
    use crate::handshake::ClientState;

    let (poll, send_task) = process_client(state, now_ms, ctx, record_queue, conn, rng)?;
    if let Some(send_task) = send_task {
        record_queue.send_rt_entry(
            send_task.entry,
            staging_buffer,
            &mut conn.epochs,
            send_task.epoch,
            send_bytes,
        )?;
    }
    let rt_poll = record_queue.run_retransmission(
        now_ms,
        staging_buffer,
        &mut conn.epochs,
        conn.current_epoch as u8,
        send_bytes,
    )?;
    if matches!(state, ClientState::WaitServerAck) && rt_poll == DtlsPoll::Wait {
        trace!("[Client] Received server ACK");
        *state = ClientState::FinishedHandshake;
        Ok(DtlsPoll::FinishedHandshake)
    } else {
        Ok(poll.merge(rt_poll))
    }
}

pub fn process_server_sync(
    state: &mut ServerState,
    now_ms: &u64,
    ctx: &mut HandshakeContext,
    record_queue: &mut RecordQueue<'_>,
    conn: &mut DtlsConnection,
    rng: &mut dyn rand_core::CryptoRngCore,
    mut staging_buffer: &mut [u8],
    send_bytes: &mut dyn FnMut(&[u8]),
) -> Result<DtlsPoll, DtlsError> {
    let (poll, send) = process_server(state, now_ms, ctx, record_queue, conn, rng)?;
    if send {
        let b = &mut staging_buffer;
        let e = &mut conn.epochs;
        record_queue.send_rt_entry(0, b, e, 0, send_bytes)?;
        record_queue.send_rt_entry(1, b, e, 2, send_bytes)?;
        record_queue.send_rt_entry(2, b, e, 2, send_bytes)?;
    }
    let rt_poll = record_queue.run_retransmission(
        now_ms,
        staging_buffer,
        &mut conn.epochs,
        conn.current_epoch as u8,
        send_bytes,
    )?;
    Ok(poll.merge(rt_poll))
}
