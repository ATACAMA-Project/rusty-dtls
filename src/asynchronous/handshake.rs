use log::trace;

use crate::{
    DtlsConnection, DtlsError, DtlsPoll, HandshakeSlotIndex, RecordQueue, StackContext,
    Milliseconds, UserSettings,
    handshake::{ClientState, HandshakeContext, ServerState, process_client, process_server},
};

use super::SocketAndAddr;

pub async fn process_client_async<Socket: embedded_nal_async::UnconnectedUdp>(
    stk_ctx: &mut StackContext<'_>,
    socket: &mut SocketAndAddr<'_, Socket>,
    index: HandshakeSlotIndex,
    ctx: &mut HandshakeContext,
    state: &mut ClientState,
    record_queue: &mut RecordQueue<'_>,
    set: &UserSettings<'_>,
    conn: &mut DtlsConnection<'_>,
    now_ms: &Milliseconds,
) -> Result<DtlsPoll, DtlsError> {
    let (poll, send_task) = process_client(
        stk_ctx.rng,
        index,
        ctx,
        state,
        record_queue,
        set,
        conn,
        now_ms,
    )?;
    if let Some(send_task) = send_task {
        record_queue
            .send_rt_entry_async(
                send_task.entry,
                stk_ctx.staging_buffer,
                &mut conn.epochs,
                send_task.epoch,
                socket,
            )
            .await?;
    }
    let rt_poll = record_queue
        .run_retransmission_async(
            stk_ctx.staging_buffer,
            socket,
            &mut conn.epochs,
            conn.current_epoch as u8,
            now_ms,
        )
        .await?;
    if matches!(state, ClientState::WaitServerAck) && rt_poll == DtlsPoll::Wait {
        trace!("[Client] Received server ACK");
        *state = ClientState::FinishedHandshake;
        Ok(DtlsPoll::FinishedHandshake(index))
    } else {
        Ok(poll.merge(rt_poll))
    }
}

pub async fn process_server_async<Socket: embedded_nal_async::UnconnectedUdp>(
    stk_ctx: &mut StackContext<'_>,
    socket: &mut SocketAndAddr<'_, Socket>,
    index: HandshakeSlotIndex,
    ctx: &mut HandshakeContext,
    state: &mut ServerState,
    record_queue: &mut RecordQueue<'_>,
    conn: &mut DtlsConnection<'_>,
    now_ms: &Milliseconds,
) -> Result<DtlsPoll, DtlsError> {
    let (poll, send) = process_server(stk_ctx.rng, index, ctx, state, record_queue, conn, now_ms)?;
    if send {
        let b = &mut stk_ctx.staging_buffer;
        let e = &mut conn.epochs;
        record_queue.send_rt_entry_async(0, b, e, 0, socket).await?;
        record_queue.send_rt_entry_async(1, b, e, 2, socket).await?;
        record_queue.send_rt_entry_async(2, b, e, 2, socket).await?;
    }
    let rt_poll = record_queue
        .run_retransmission_async(
            stk_ctx.staging_buffer,
            socket,
            &mut conn.epochs,
            conn.current_epoch as u8,
            now_ms,
        )
        .await?;
    Ok(poll.merge(rt_poll))
}
