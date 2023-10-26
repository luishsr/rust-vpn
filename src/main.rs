extern crate serde_derive;
extern crate tun;

use std::io::Read;
use anyhow::Result;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use bincode::{config, deserialize, serialize};
use clap::{App, Arg};
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tun::platform::{Configuration, Device};

const KEY: [u8; 32] = [0u8; 32]; // Replace with your AES key
const NONCE_LEN: usize = 12;

#[derive(Serialize, Deserialize)]
struct VpnPacket {
    data: Vec<u8>,
}

async fn handle_client(mut stream: TcpStream, tun: Arc<Mutex<Device>>) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(n) if n > 0 => {
                let packet: VpnPacket = deserialize(&buf[..n]).unwrap();
                let decrypted_data = decrypt(&packet.data, &KEY).unwrap();
                let mut locked_tun = tun.lock().await;
                locked_tun.write(&decrypted_data);
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error reading: {:?}", e);
                break;
            }
        }
    }
    Ok(())
}

fn encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = rand::thread_rng().gen::<[u8; NONCE_LEN]>();
    cipher.encrypt(&nonce.into(), data).unwrap()
}

fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, aes_gcm::aead::Error> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = &data[0..NONCE_LEN];
    cipher.decrypt(nonce.into(), &data[NONCE_LEN..])
}

fn set_client_ip_and_route() {
    let ip_output = Command::new("ip")
        .arg("addr")
        .arg("add")
        .arg("10.0.0.2/24")
        .arg("dev")
        .arg("tun0")
        .output()
        .expect("Failed to execute IP command");

    if !ip_output.status.success() {
        eprintln!("Failed to set IP: {}", String::from_utf8_lossy(&ip_output.stderr));
        return;
    }

    let link_output = Command::new("ip")
        .arg("link")
        .arg("set")
        .arg("up")
        .arg("dev")
        .arg("tun0")
        .output()
        .expect("Failed to execute IP LINK command");

    if !link_output.status.success() {
        eprintln!("Failed to set link up: {}", String::from_utf8_lossy(&link_output.stderr));
        return;
    }

    let route_output = Command::new("ip")
        .arg("route")
        .arg("add")
        .arg("0.0.0.0/0")
        .arg("via")
        .arg("10.0.0.1")
        .arg("dev")
        .arg("tun0")
        .output()
        .expect("Failed to execute IP ROUTE command");

    if !route_output.status.success() {
        eprintln!("Failed to set route: {}", String::from_utf8_lossy(&route_output.stderr));
    }
}

#[tokio::main]
async fn main() {
    let matches = App::new("Simple VPN")
        .version("1.0")
        .author("Luis Soares")
        .about("A simple VPN tunnel in Rust")
        .arg(Arg::with_name("mode")
            .required(true)
            .index(1)
            .possible_values(&["server", "client"])
            .help("Runs the program in either server or client mode"))
        .get_matches();

    let is_server_mode = matches.value_of("mode").unwrap() == "server";

    if is_server_mode {
        // Server mode setup
        let listener = TcpListener::bind("0.0.0.0:12345").await.unwrap();

        let mut config = tun::Configuration::default();
        let tun_device = tun::create(&config).unwrap();
        let shared_tun = Arc::new(Mutex::new(tun_device));

        println!("Server listening...");
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(handle_client(stream, shared_tun.clone()));
        }
    } else {
        // Client mode setup
        set_client_ip_and_route();
        let mut stream = TcpStream::connect("server_ip:12345").await.unwrap();

        let mut config = tun::Configuration::default();
        let mut tun_device = tun::create(&config).unwrap();


        loop {
            let mut buf = vec![0u8; 4096];
            let n = tun_device.read(&mut buf).unwrap();
            if n > 0 {
                let encrypted_data = encrypt(&buf[..n], &KEY);
                let packet = VpnPacket { data: encrypted_data };
                let serialized_data = serialize(&packet).unwrap();
                let _ = stream.write_all(&serialized_data).await;
            }
        }
    }
}
