extern crate serde_derive;
extern crate tun;

use std::error::Error;
use std::io::Read;
use anyhow::Result;
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use aes_gcm::aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes_soft::cipher::NewStreamCipher;
use bincode::{config, deserialize, serialize};
use block_modes::{BlockMode, Cbc};
use clap::{App, Arg};
use generic_array::GenericArray;
use rand::Rng;
use std::error::Error as StdError;
use serde_derive::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
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

                println!("Packet received on VPN Server {:?}", packet.data);

                let mut locked_tun = tun.lock().await;

                println!("Forwarding packet to tun0");

                locked_tun.write_all(&packet.data);

                println!("Sent.");

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

fn to_fixed_size_array(slice: &[u8]) -> Option<[u8; 32]> {
    if slice.len() != 32 {
        return None;
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(slice);
    Some(array)
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
            let stream = Arc::new(Mutex::new(stream)); // Wrap in Arc<Mutex<>>

            println!("Connected.");

            let mut config = tun::Configuration::default();
            config.name("tun0");

            let tun_device = Arc::new(Mutex::new(tun::create(&config).unwrap()));

            // Client mode setup
            set_client_ip_and_route();

            // Clone the Arc reference for each task
            let stream_for_writing = stream.clone();
            let stream_for_reading = stream.clone();

            let tun_device_for_write = tun_device.clone();
            let write_to_server = tokio::spawn(async move {
                loop {

                    println!("Reading from the tun0 to write data to Server");

                    let mut buf = vec![0u8; 4096];
                    match tun_device_for_write.lock().await.read(&mut buf) {
                        Ok(n) if n > 0 => {
                            let encrypted_data = encrypt(&buf[..n]);
                            let packet = VpnPacket { data: encrypted_data };
                            let serialized_data = serialize(&packet).unwrap();

                            let mut locked_stream = stream_for_writing.lock().await;
                            let _ = locked_stream.write_all(&serialized_data).await;

                            println!("Data sent to Server");
                        }
                        Ok(_) => {
                            println!("Nothing to read");
                        },
                        Err(e) => {
                            eprintln!("Error reading from TUN device: {}", e);
                        }
                    }
                }
            });

            // Task for reading from the server and writing to TUN
            let tun_device_for_read = tun_device.clone();
            let read_from_server = tokio::spawn(async move {
                loop {
                    println!("Task for reading from the server initiated");

                    let mut buf = vec![0u8; 4096];
                    let mut locked_stream = stream_for_reading.lock().await;

                    println!("Reading from Server - line 301");

                    match locked_stream.read(&mut buf).await {
                        Ok(n) if n > 0 => {

                            println!("Ok(n) if n > 0 is TRUE");


                            let mut packet: VpnPacket = deserialize(&buf[..n]).unwrap();
                            let decrypted_data = decrypt(&packet.data);

                            // TODO: Implement forward and response
                            //////// ADD FORWARDING LOGIC HERE ///////////////


                            packet.data.truncate(n);

                            if let Some(ip_header) = extract_ipv4_header(&decrypted_data) {

                                println!("Extracted IPV4 Header");

                                if ip_header.protocol == 6 {

                                    println!("Protocol == 6");

                                    if let Some(tcp_header) = extract_tcp_header(&packet.data[20..]) {
                                        match forward_packet_to_destination(&packet.data, ip_header.daddr, tcp_header.dest_port) {
                                            Ok(response) => {
                                                let _ = tun_device_for_read.lock().await.write_all(&response);
                                            },
                                            Err(e) => {
                                                println!("Error forwarding packet: {}", e);
                                            }
                                        }
                                    }
                                }
                            }

                            ///////// END OF FORWARD LOGIC ///////

                        }
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Error reading from server: {:?}", e);
                            break;
                        }
                    }
                }
            });

            // Wait for the tasks to complete
            let _ = tokio::try_join!(write_to_server, read_from_server);
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

struct Ipv4Header {
    version: u8,
    ihl: u8,
    tot_len: u16,
    id: u16,
    flags: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    saddr: [u8; 4],
    daddr: [u8; 4],
}

struct TcpHeader {
    source_port: u16,
    dest_port: u16,
    // ... Other TCP header fields ...
}

fn extract_ipv4_header(packet: &[u8]) -> Option<Ipv4Header> {
    if packet.len() < 20 {
        return None;
    }

    Some(Ipv4Header {
        version: packet[0] >> 4,
        ihl: packet[0] & 0xF,
        tot_len: u16::from_be_bytes([packet[2], packet[3]]),
        id: u16::from_be_bytes([packet[4], packet[5]]),
        flags: u16::from_be_bytes([packet[6], packet[7]]),
        ttl: packet[8],
        protocol: packet[9],
        checksum: u16::from_be_bytes([packet[10], packet[11]]),
        saddr: [packet[12], packet[13], packet[14], packet[15]],
        daddr: [packet[16], packet[17], packet[18], packet[19]],
    })
}

fn extract_tcp_header(packet: &[u8]) -> Option<TcpHeader> {
    if packet.len() < 20 {
        return None;
    }

    Some(TcpHeader {
        source_port: u16::from_be_bytes([packet[0], packet[1]]),
        dest_port: u16::from_be_bytes([packet[2], packet[3]]),
        // ... Extract other TCP fields as needed ...
    })
}

fn forward_packet_to_destination(packet: &[u8], dest_ip: [u8; 4], dest_port: u16) -> Result<Vec<u8>, Box<dyn StdError + Send>> {
    println!("Server forwarding packet to destination {:?}", dest_ip);
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(|e| Box::new(e) as Box<dyn StdError + Send>)?;
    let address_string = format!("{}.{}.{}.{}:{}", dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3], dest_port);
    let address: SocketAddr = address_string.parse().unwrap();

    socket.send_to(packet, &address.into()).map_err(|e| Box::new(e) as Box<dyn StdError + Send>)?;


    let mut response = vec![0u8; 4096];
    let mut uninitialized: [MaybeUninit<u8>; 4096] = unsafe { MaybeUninit::uninit().assume_init() };
    let (amt, _) = socket.recv_from(&mut uninitialized).map_err(|e| Box::new(e) as Box<dyn StdError + Send>)?;
    for i in 0..amt {
        response[i] = unsafe { uninitialized[i].assume_init() };
    }
    response.truncate(amt);

    Ok(response)
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
