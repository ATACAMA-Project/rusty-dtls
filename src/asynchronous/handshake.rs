use log::trace;

use crate::{
    handshake::{process_client, process_server, ClientState, HandshakeContext, ServerState},
    DtlsConnection, DtlsError, DtlsPoll, RecordQueue, TimeStampMs,
};

use super::SocketAndAddr;

pub async fn process_client_async<Socket: embedded_nal_async::UnconnectedUdp>(
    state: &mut ClientState,
    now_ms: &TimeStampMs,
    ctx: &mut HandshakeContext<'_>,
    record_queue: &mut RecordQueue<'_>,
    conn: &mut DtlsConnection<'_>,
    rng: &mut dyn rand_core::CryptoRngCore,
    staging_buffer: &mut [u8],
    socket: &mut SocketAndAddr<'_, Socket>,
) -> Result<DtlsPoll, DtlsError> {
    let (poll, send_task) = process_client(state, now_ms, ctx, record_queue, conn, rng)?;
    if let Some(send_task) = send_task {
        record_queue
            .send_rt_entry_async(
                send_task.entry,
                staging_buffer,
                &mut conn.epochs,
                send_task.epoch,
                socket,
            )
            .await?;
    }
    let rt_poll = record_queue
        .run_retransmission_async(
            now_ms,
            staging_buffer,
            &mut conn.epochs,
            conn.current_epoch as u8,
            socket,
        )
        .await?;
    if matches!(state, ClientState::WaitServerAck) && rt_poll == DtlsPoll::Wait {
        trace!("[Client] Received server ACK");
        *state = ClientState::FinishedHandshake;
        Ok(DtlsPoll::FinishedHandshake)
    } else {
        Ok(poll.merge(rt_poll))
    }
}

pub async fn process_server_async<Socket: embedded_nal_async::UnconnectedUdp>(
    state: &mut ServerState,
    now_ms: &TimeStampMs,
    ctx: &mut HandshakeContext<'_>,
    record_queue: &mut RecordQueue<'_>,
    conn: &mut DtlsConnection<'_>,
    rng: &mut dyn rand_core::CryptoRngCore,
    mut staging_buffer: &mut [u8],
    socket: &mut SocketAndAddr<'_, Socket>,
) -> Result<DtlsPoll, DtlsError> {
    let (poll, send) = process_server(state, now_ms, ctx, record_queue, conn, rng)?;
    if send {
        let b = &mut staging_buffer;
        let e = &mut conn.epochs;
        record_queue.send_rt_entry_async(0, b, e, 0, socket).await?;
        record_queue.send_rt_entry_async(1, b, e, 2, socket).await?;
        record_queue.send_rt_entry_async(2, b, e, 2, socket).await?;
    }
    let rt_poll = record_queue
        .run_retransmission_async(
            now_ms,
            staging_buffer,
            &mut conn.epochs,
            conn.current_epoch as u8,
            socket,
        )
        .await?;
    Ok(poll.merge(rt_poll))
}
