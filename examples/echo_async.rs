use embedded_nal_async::UdpStack;
use rusty_dtls::{DtlsStackAsync, HandshakeSlot, HashFunction, Psk};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use tokio::main;

async fn spawn_endpoint(port: u16, peer_port: u16, server: bool) {
    println!("Bound on port {}", port);
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
            port,
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

    let mut id = None;
    loop {
        if !server {
            if let Some(id) = id {
                stack
                    .send_dtls_packet(id, "Hello World".as_bytes())
                    .await
                    .unwrap();
            }
        }
        println!("[{port}] Read");
        let e = stack.read(&mut handshakes, 5000).await;
        match e.unwrap() {
            rusty_dtls::Event::AppData(_, range) => {
                println!(
                    "[{port}] Appdata: {}",
                    String::from_utf8_lossy(&stack.staging_buffer()[range])
                );
            }
            rusty_dtls::Event::OpenedConnection => {
                id = handshakes[0].try_take_connection_id();
                println!("[{port}] Opened conid {id:?}");
            }
            _ => {}
        };
    }
}

#[main]
async fn main() {
    let _ = simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init();

    tokio::join! {
        spawn_endpoint(62447, 50402, true),
        spawn_endpoint(50402, 62447, false),
    };
}
