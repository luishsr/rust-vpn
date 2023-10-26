extern crate serde_derive;
extern crate tun;

use std::error::Error;
use std::io::Read;
use anyhow::Result;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use aes_gcm::aes::Aes256;
use aes_gcm::aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes_soft::cipher::NewStreamCipher;
use bincode::{config, deserialize, serialize};
use block_modes::{BlockMode, Cbc};
use block_padding::Pkcs7;
use clap::{App, Arg};
use generic_array::GenericArray;
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tun::platform::{Configuration, Device};


const KEY: [u8; 32] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const NONCE: [u8; 12] = [0; 12];  // Using a constant nonce for simplicity; in a real application, each nonce should be unique

fn encrypt(data: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(&KEY);
    let nonce = GenericArray::from_slice(&NONCE);
    let cipher = Aes256Gcm::new(key);

    let ciphertext = cipher.encrypt(nonce, data.as_ref()).expect("encryption failure!");
    ciphertext
}

fn decrypt(encrypted_data: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(&KEY);
    let nonce = GenericArray::from_slice(&NONCE);
    let cipher = Aes256Gcm::new(key);

    let decrypted_data = cipher.decrypt(nonce, encrypted_data.as_ref()).expect("decryption failure!");
    decrypted_data
}

#[derive(Serialize, Deserialize)]
struct VpnPacket {
    data: Vec<u8>,
}

async fn handle_client(mut stream: TcpStream, tun: Arc<Mutex<Device>>) -> Result<()> {

    // Get the peer address and print it
    let peer_address = stream.peer_addr().unwrap_or_else(|_| "Unknown peer".to_string().parse().unwrap());

    println!("Client {} connected to the VPN.", peer_address);

    let mut buf = vec![0u8; 4096];

    loop {
        match stream.read(&mut buf).await {
            Ok(n) if n > 0 => {
                let packet: VpnPacket = deserialize(&buf[..n]).unwrap();

                let data_array: [u8; 32] = packet.data.try_into().expect("Failed to convert to fixed-size array");

                //let decrypted_data = decrypt(&data_array);

                let mut locked_tun = tun.lock().await;

                locked_tun.write(&data_array);

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

fn set_client_ip_and_route() {
    let ip_output = Command::new("ip")
        .arg("addr")
        .arg("add")
        .arg("10.8.0.2/24")
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
        .arg("10.8.0.1")
        .arg("dev")
        .arg("tun0")
        .output()
        .expect("Failed to execute IP ROUTE command");

    if !route_output.status.success() {
        eprintln!("Failed to set route: {}", String::from_utf8_lossy(&route_output.stderr));
    }
}

fn setup_tun_interface() -> Result<(), Box<dyn Error>> {
    let output = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("set")
        .arg("dev")
        .arg("tun0")
        .arg("up")
        .output()?;

    if !output.status.success() {
        return Err(format!("Failed to bring up tun0: {:?}", output.stderr).into());
    }

    let output = Command::new("sudo")
        .arg("ip")
        .arg("addr")
        .arg("add")
        .arg("10.8.0.1/24")
        .arg("dev")
        .arg("tun0")
        .output()?;

    if !output.status.success() {
        return Err(format!("Failed to assign IP to tun0: {:?}", output.stderr).into());
    }

    Ok(())
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
        .arg(Arg::with_name("vpn-server")
            .long("vpn-server")
            .value_name("IP")
            .help("The IP address of the VPN server to connect to (client mode only)")
            .takes_value(true))
        .get_matches();


    let is_server_mode = matches.value_of("mode").unwrap() == "server";

    if is_server_mode {
        // Server mode setup
        let listener = TcpListener::bind("0.0.0.0:12345").await.unwrap();

        let mut config = tun::Configuration::default();

        config.name("tun0");

        let tun_device = tun::create(&config).unwrap();

        let shared_tun = Arc::new(Mutex::new(tun_device));

        setup_tun_interface();

        println!("Server listening...");

        let shutdown_signal = Arc::new(AtomicBool::new(false));

        // Spawn a task to listen for the Ctrl+C signal
        let signal_listener = {
            let shutdown_signal = shutdown_signal.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl_c");
                shutdown_signal.store(true, Ordering::SeqCst);
            })
        };

        // Wait for a shutdown signal
        loop {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept()).await {
                Ok(Ok((stream, _))) => {
                    tokio::spawn(handle_client(stream, shared_tun.clone()));
                }
                Ok(Err(e)) => {
                    eprintln!("Error accepting connection: {}", e);
                }
                Err(_) => {
                    // Timeout
                    if shutdown_signal.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }
        }

        // Here, you might want to give active tasks a moment to finish before forcing them to shut down.
        // For example:
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // If we reach here, it means a shutdown signal was received.
        destroy_tun_interface().await;

        // Optionally, you can wait for the signal_listener to complete
        signal_listener.await.expect("Signal listener task failed");

    } else {
        if let Some(vpn_server_ip) = matches.value_of("vpn-server") {
            println!("Connecting to VPN server on {}", vpn_server_ip);

            // Use vpn_server_ip for setting up the client connection
            let server_address = format!("{}:12345", vpn_server_ip);

            let mut stream = TcpStream::connect(server_address).await.unwrap();

            let mut config = tun::Configuration::default();
            config.name("tun0");
            let mut tun_device = tun::create(&config).unwrap();

            // Client mode setup
            set_client_ip_and_route();

            loop {
                let mut buf = vec![0u8; 4096];
                let n = tun_device.read(&mut buf).unwrap();
                if n > 0 {

                    let mut data_to_encrypt = [0u8; 32];

                    //data_to_encrypt[..n].copy_from_slice(&buf[..n]);

                    let encrypted_data = encrypt(&data_to_encrypt);
                    let packet = VpnPacket { data: Vec::from(encrypted_data) };
                    let serialized_data = serialize(&packet).unwrap();

                    let _ = stream.write_all(&serialized_data).await;
                }
            }
        } else {
            eprintln!("The vpn-server IP address is required for client mode!");
            return;
        }
    }
}

async fn destroy_tun_interface() {
    let output = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("delete")
        .arg("tun0")
        .output()
        .expect("Failed to execute command to delete TUN interface");

    if !output.status.success() {
        eprintln!("Failed to delete TUN interface: {}", String::from_utf8_lossy(&output.stderr));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    #[test]
    fn test_encryption_decryption() {
        let original = b"hello";

        // Encrypt the original data
        let mut data_to_encrypt = [0u8; 32]; // Initialize an array with zeros
        data_to_encrypt[..original.len()].copy_from_slice(original); // Copy the data from 'original' into the array
        let encrypted = encrypt(&data_to_encrypt);

        // Ensure the encrypted data isn't the same as the original
        assert_ne!(&encrypted[..], original);

        // Decrypt the encrypted data
        let decrypted = decrypt(&encrypted);

        // Convert decrypted to a slice and trim trailing null bytes
        let trimmed_decrypted = &decrypted[..original.len()];

        assert_eq!(original, trimmed_decrypted);
    }
}
