use clap::{App, Arg};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::thread;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::error::Error;
use serde_derive::Serialize;
use serde_derive::Deserialize;
use generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};
use std::process::Command;
use aes_gcm::aead::Aead;
use env_logger::Builder;
use tun::platform::Device;
use log::{error, info, LevelFilter};


const KEY: [u8; 32] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const NONCE: [u8; 12] = [0; 12];  // Using a constant nonce for simplicity; in a real application, each nonce should be unique

fn encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    let key = GenericArray::from_slice(&KEY);
    let nonce = GenericArray::from_slice(&NONCE);
    let cipher = Aes256Gcm::new(key);

    match cipher.encrypt(nonce, data.as_ref()) {
        Ok(ciphertext) => Ok(ciphertext),
        Err(_) => Err("Encryption failure!".to_string())
    }
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

#[derive(Debug)]
enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
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

#[derive(Debug)]
struct Ipv6Header {
    version: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    source_address: [u8; 16],
    destination_address: [u8; 16],
}

fn handle_client(client_id: usize, mut stream: TcpStream, clients: Arc<Mutex<HashMap<usize, TcpStream>>>) {
    let mut buffer = [0; 1024];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                info!("Client {} disconnected", client_id);
                break;
            }
            Ok(n) => {
                let data = &buffer[0..n];

                info!("Server: data received from the client: {:?}", data);

                let mut clients_guard = clients.lock().unwrap();

                for (id, client_stream) in clients_guard.iter_mut() {
                    if *id != client_id {
                        let _ = client_stream.write(data);
                    }
                }
            }
            Err(e) => {
                error!("Error reading from client {}: {}", client_id, e);
                break;
            }
        }
    }

    clients.lock().unwrap().remove(&client_id);
    let _ = stream.shutdown(Shutdown::Both);
}

fn server_mode() {
    // Existing server logic
    let listener = TcpListener::bind("0.0.0.0:12345").unwrap();
    let clients: Arc<Mutex<HashMap<usize, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut config = tun::Configuration::default();
    config.name("tun0");
    let tun_device = tun::create(&config).unwrap();

    // Setup the tun0 interface
    if let Err(e) = setup_tun_interface() {
        eprintln!("Failed to set up TUN interface: {}", e);
        return;
    }

    let shared_tun = Arc::new(Mutex::new(tun_device));

    info!("Server started on 0.0.0.0:12345");

    let tun_device_clone = shared_tun.clone();
    let clients_clone = clients.clone();

    thread::spawn(move || {
        let clients_guard = clients_clone.lock().unwrap();

        if let Some(client) = clients_guard.get(&0) {
            if let Ok(client_clone) = client.try_clone() {
                drop(clients_guard);  // Unlock the mutex early
                let mut locked_tun = tun_device_clone.lock().unwrap();
                read_from_tun_and_send_to_client(&mut *locked_tun, client_clone);
            } else {
                // Handle error while trying to clone the TcpStream
                println!("Failed to clone client TcpStream");
            }
        } else {
            // Handle the case where the client doesn't exist
            println!("No client with key 0 found");
        }
    });

    for (client_id, stream) in listener.incoming().enumerate() {
        match stream {
            Ok(stream) => {
                info!("New client connected with ID: {}", client_id); // This line is added

                if client_id == 0 {  // For now, only starting TUN data handling for the first client
                    let tun_device_clone = shared_tun.clone();
                    let clients_clone = clients.clone();

                    thread::spawn(move || {
                        let client_clone = clients_clone.lock().unwrap().get(&0).unwrap().try_clone().unwrap();
                        let mut locked_tun = tun_device_clone.lock().unwrap();
                        read_from_tun_and_send_to_client(&mut *locked_tun, client_clone);
                    });
                }
                clients.lock().unwrap().insert(client_id, stream.try_clone().unwrap());
                let clients_arc = clients.clone();
                thread::spawn(move || handle_client(client_id, stream, clients_arc));
            }
            Err(e) => {
                error!("Connection failed: {}", e);
            }
        }
    }

    // Clean up the tun0 interface when done
    destroy_tun_interface();
}

const TUN_INTERFACE_NAME: &str = "tun0";

fn read_from_tun_and_send_to_client<T: tun::Device>(tun: &mut T, mut client: TcpStream) {
    let mut buffer = [0u8; 1500];

    loop {
        match tun.read(&mut buffer) {
            Ok(n) => {
                match encrypt(&buffer[..n]) {
                    Ok(encrypted_data) => {
                        // Handle sending the encrypted data to the client
                        info!("Received {} bytes from TUN device.", n);

                        let vpn_packet = VpnPacket { data: encrypted_data };
                        // Serialize and send to client
                        let serialized_data = bincode::serialize(&vpn_packet).unwrap();

                        client.write_all(&serialized_data).unwrap();
                        info!("Forwarded {} bytes to destination.", n);

                    },
                    Err(err_msg) => {
                        // Handle the encryption error
                        error!("Encryption error: {}", err_msg);
                    }
                }
            },
            Err(e) => {
                // Handle the TUN reading error
                error!("TUN read error: {}", e);
            }
        }
    }

}

async fn read_from_client_and_write_to_tun(client: &mut TcpStream, tun: &mut Device) {
    let mut buffer = [0u8; 1500];
    loop {
        let n = match client.read(&mut buffer) {
            Ok(n) => n,
            Err(e) => {
                error!("Error reading from client: {}", e);
                continue; // or return based on how you want to handle it
            }
        };

        let vpn_packet: VpnPacket = bincode::deserialize(&buffer[..n]).unwrap();
        let decrypted_data = decrypt(&vpn_packet.data);

        info!("Writing data to tun0: {}", String::from_utf8_lossy(decrypted_data.as_slice()));

        tun.write(&decrypted_data).unwrap();
    }
}

async fn client_mode(vpn_server_ip: &str) {
    // Basic client mode for demonstration
    let mut stream = TcpStream::connect(vpn_server_ip).unwrap();

    // Clone the stream so you can use it both inside and outside the async block
    let mut stream_clone = stream.try_clone().unwrap();

    let mut config = tun::Configuration::default();
    config.name("tun0");
    let mut tun_device = tun::create(&config).unwrap();

    // Set the client's IP and routing
    set_client_ip_and_route();

    info!("Connected to the server {}", vpn_server_ip);

    let mut buffer = [0; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(n) => {
                info!("{} Received from the server", n);
                read_from_client_and_write_to_tun(&mut stream_clone, &mut tun_device).await;
            }
            Err(_) => {
                break;
            }
        }
    }
}

#[tokio::main]
async fn  main() {

    // Initialize the logger with 'info' as the default level
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();

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
        server_mode();
    } else {
        if let Some(vpn_server_ip) = matches.value_of("vpn-server") {
            let server_address = format!("{}:12345", vpn_server_ip);
            client_mode(server_address.as_str()).await;
        } else {
            eprintln!("Error: For client mode, you must provide the '--vpn-server' argument.");
        }
    }
}