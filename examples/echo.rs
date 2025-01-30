use {
    core::time::Duration,
    rusty_dtls::ConnectionId,
    rusty_dtls::{DtlsPoll, DtlsStack, HandshakeSlot, HashFunction, Psk, NetQueue},
    std::net::SocketAddr,
    std::net::UdpSocket,
    std::ops::Range,
    std::sync::Mutex,
    std::thread,
    std::time::Instant,
};

fn spawn_endpoint(port: u16, peer_port: u16, server: bool) {
    let socket = Mutex::new(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port))).unwrap());
    println!(
        "Bound on port {}",
        socket.lock().unwrap().local_addr().unwrap().port()
    );
    let mut send_to_peer = |addr: &SocketAddr, buf: &[u8]| {
        socket.lock().unwrap().send_to(buf, addr).unwrap();
    };
    let mut receive_buf = [0; 128];
    let mut handle_app_data =
        |id: ConnectionId, data: Range<usize>, stack: &mut DtlsStack<'_, 10>| {
            let len = data.end - data.start;
            if server {
                println!("[{port}] Received application data");
                let len = receive_buf.len().min(len);
                receive_buf[..len]
                    .copy_from_slice(&stack.staging_buffer()[data.start..data.start + len]);
                let _ = stack.send_dtls_packet(id, &receive_buf[..len]);
            } else {
                println!(
                    "[{port}] Received application data: {:?}",
                    String::from_utf8_lossy(&stack.staging_buffer()[data])
                );
            }
        };

    let mut net_queue = NetQueue::new();
    let mut staging_buffer = [0; 256];
    let mut rand = rand::thread_rng();
    let psks = [Psk::new(&[123], &[1, 2, 3, 4, 5], HashFunction::Sha256)];
    let mut stack =
        DtlsStack::<10>::new(&mut rand, &mut staging_buffer, &mut send_to_peer).unwrap();
    stack.require_cookie(false);

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
    let mut server_id = None;
    loop {
        let poll = stack
            .poll(&mut handshakes, start.elapsed().as_millis() as u64)
            .unwrap();
        match poll {
            DtlsPoll::WaitTimeoutMs(ms) => {
                println!("[{port}] Wait {ms}");
                socket
                    .lock()
                    .unwrap()
                    .set_read_timeout(Some(Duration::from_millis(ms as u64)))
                    .unwrap();
                let Ok((received, addr)) = socket.lock().unwrap().recv_from(stack.staging_buffer())
                else {
                    continue;
                };
                stack
                    .handle_dtls_packet(&mut handshakes, &addr, received, &mut handle_app_data)
                    .unwrap();
            }
            DtlsPoll::Wait => {
                println!("[{port}] Wait");
                socket
                    .lock()
                    .unwrap()
                    .set_read_timeout(if server_id.is_some() {
                        Some(Duration::from_millis(5000_u64))
                    } else {
                        None
                    })
                    .unwrap();
                let Ok((received, addr)) = socket.lock().unwrap().recv_from(stack.staging_buffer())
                else {
                    if let Some(id) = server_id {
                        stack
                            .send_dtls_packet(id, "Hello World".as_bytes())
                            .unwrap();
                    }
                    continue;
                };
                stack
                    .handle_dtls_packet(&mut handshakes, &addr, received, &mut handle_app_data)
                    .unwrap();
            }
            DtlsPoll::FinishedHandshake => {
                for hs in &mut handshakes {
                    let Some(id) = hs.try_take_connection_id() else {
                        continue;
                    };
                    if !server {
                        server_id = Some(id);
                    }
                    println!("[{port}] Got connection id: {:?}", id);
                }
            }
        }
    }
}

fn main() {
    let _ = simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init();

    let t1 = thread::spawn(|| {
        spawn_endpoint(62447, 50402, true);
    });
    let t2 = thread::spawn(|| {
        spawn_endpoint(50402, 62447, false);
    });
    t1.join().unwrap();
    t2.join().unwrap();
}
