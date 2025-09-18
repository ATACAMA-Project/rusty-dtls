use log::trace;

use crate::{
    DtlsConnection, DtlsError, DtlsPoll, HandshakeSlotIndex, RecordQueue, StackContext,
    Milliseconds, UserSettings,
    handshake::{ClientState, HandshakeContext, ServerState, process_client, process_server},
};

pub fn process_client_sync(
    stk_ctx: &mut StackContext,
    send_bytes: &mut dyn FnMut(&[u8]),
    index: HandshakeSlotIndex,
    ctx: &mut HandshakeContext,
    state: &mut ClientState,
    record_queue: &mut RecordQueue<'_>,
    set: &UserSettings,
    conn: &mut DtlsConnection,
    now_ms: &Milliseconds,
) -> Result<DtlsPoll, DtlsError> {
    use crate::handshake::ClientState;

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
        record_queue.send_rt_entry(
            send_task.entry,
            stk_ctx.staging_buffer,
            &mut conn.epochs,
            send_task.epoch,
            send_bytes,
        )?;
    }
    let rt_poll = record_queue.run_retransmission(
        stk_ctx.staging_buffer,
        send_bytes,
        &mut conn.epochs,
        conn.current_epoch as u8,
        now_ms,
    )?;
    if matches!(state, ClientState::WaitServerAck) && rt_poll == DtlsPoll::Wait {
        trace!("[Client] Received server ACK");
        *state = ClientState::FinishedHandshake;
        Ok(DtlsPoll::FinishedHandshake(index))
    } else {
        Ok(poll.merge(rt_poll))
    }
}

pub fn process_server_sync(
    stk_ctx: &mut StackContext,
    send_bytes: &mut dyn FnMut(&[u8]),
    index: HandshakeSlotIndex,
    ctx: &mut HandshakeContext,
    state: &mut ServerState,
    record_queue: &mut RecordQueue<'_>,
    conn: &mut DtlsConnection,
    now_ms: &Milliseconds,
) -> Result<DtlsPoll, DtlsError> {
    let (poll, send) = process_server(stk_ctx.rng, index, ctx, state, record_queue, conn, now_ms)?;
    if send {
        let b = &mut stk_ctx.staging_buffer;
        let e = &mut conn.epochs;
        record_queue.send_rt_entry(0, b, e, 0, send_bytes)?;
        record_queue.send_rt_entry(1, b, e, 2, send_bytes)?;
        record_queue.send_rt_entry(2, b, e, 2, send_bytes)?;
    }
    let rt_poll = record_queue.run_retransmission(
        stk_ctx.staging_buffer,
        send_bytes,
        &mut conn.epochs,
        conn.current_epoch as u8,
        now_ms,
    )?;
    Ok(poll.merge(rt_poll))
}
