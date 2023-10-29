# rust-vpn

A basic VPN tunnel implementation written in Rust.

## Overview

Simple VPN is a rudimentary implementation of a VPN tunnel, allowing users to establish a virtual private connection. 
Built in Rust, it showcases the robustness and efficiency of the language while providing basic tunneling capabilities.

### Features:
- VPN Server and Client Modes.
- AES-256-GCM encryption for data security.
- TUN interface configuration for both server and client.
- Simple command-line interface using `clap`.
- Logging with different verbosity levels.

## Getting Started

### Prerequisites

- Rust and Cargo: Ensure you have the latest versions installed. If not, visit [Rust's official page](https://www.rust-lang.org/) for installation details.

### Installation

1. Clone the repository:

       git clone https://github.com/LuisSoares/simple-vpn.git
       cd simple-vpn

2. Build the application:

       cargo build --release

Usage

Server Mode:

  To start the VPN in server mode:

       cargo run server

Client Mode:

To start the VPN in client mode:

    cargo run client --vpn-server <VPN_SERVER_IP>

 Replace <VPN_SERVER_IP> with the IP address of the VPN server you wish to connect to.

Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
