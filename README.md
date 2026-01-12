# OpenVPN Certificate Generator

A Python-based OpenVPN certificate and configuration generator with TLS-crypt-v2 support. This tool simplifies the process of creating secure OpenVPN server and client configurations with embedded certificates and keys.

## Features

- **Automated Certificate Generation**: Creates CA, server, and client certificates automatically
- **TLS-crypt-v2 Support**: Implements OpenVPN's tls-crypt-v2 for additional security layer
- **Diffie-Hellman Parameters**: Generates and reuses DH parameters for secure key exchange
- **Deterministic Key Derivation**: Uses PBKDF2 for secure key derivation from seeds
- **All-in-One Configuration Files**: Generates complete OpenVPN config files with embedded certificates
- **Flexible Modes**: Generate server-only, clients-only, or complete setup
- **Multiple Client Support**: Create multiple client configurations in one run

## Requirements

- Python 3.12 or higher
- Poetry (for dependency management)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/dazzgt/openvpn-cert-gen.git
cd openvpn-cert-gen
```

2. Install dependencies using Poetry:
```bash
poetry install
```

3. Activate the virtual environment:
```bash
poetry shell
```

## Usage

### Quick Start

Generate a complete OpenVPN setup (server + client configs):

```bash
python main.py --domain your-domain.com --clients 5
```

This will create:
- Server configuration at `configs/server.conf`
- 5 client configurations at `configs/client_0`, `configs/client_1`, etc.
- CA certificates and keys in the `secrets/` directory

### Command-Line Options

```bash
python main.py [OPTIONS]
```

**Options:**

- `--mode {full,server,clients}` - Generation mode (default: `full`)
  - `full`: Generate both server and client configurations
  - `server`: Generate only server configuration
  - `clients`: Generate only client configurations

- `--clients COUNT` - Number of client configs to generate (default: 1)
  - Required when mode is `clients` or `full`
  - Must be >= 1

- `--domain DOMAIN` - Server domain name (default: `gamerex.org`)
  - Used for server certificate CN and client connection

- `--port PORT` - Server port (default: 443)
  - The port OpenVPN server will listen on

- `--proto {tcp,udp}` - Protocol (default: `tcp`)
  - Choose between TCP and UDP transport

### Examples

Generate server configuration only:
```bash
python main.py --mode server --domain vpn.example.com --port 1194 --proto udp
```

Generate 10 client configurations only:
```bash
python main.py --mode clients --clients 10 --domain vpn.example.com
```

Generate full setup with custom settings:
```bash
python main.py --mode full --domain vpn.example.com --port 1194 --proto udp --clients 3
```

## Project Structure

```
openvpn-cert-gen/
├── main.py              # Main application script
├── pyproject.toml       # Poetry configuration and dependencies
├── templates/           # OpenVPN configuration templates
│   ├── server.template  # Server configuration template
│   └── client.template  # Client configuration template
├── secrets/             # Generated keys and certificates (auto-created)
│   ├── ca.key          # Certificate Authority private key
│   ├── ca.crt          # Certificate Authority certificate
│   ├── dh.pem          # Diffie-Hellman parameters
│   ├── tc2-seed.txt    # TLS-crypt-v2 seed
│   └── tls-crypt-v2-server.key  # Server TLS-crypt-v2 key
└── configs/             # Generated OpenVPN configurations (auto-created)
    ├── server.conf      # Server configuration
    └── client_*         # Client configurations
```

## Security Features

### TLS-crypt-v2

This tool implements OpenVPN's tls-crypt-v2 protocol, which provides:
- Protection against active probing attacks
- Additional layer of HMAC authentication before TLS handshake
- Deterministic key wrapping using AES-256-CTR encryption

### Certificate Management

- 2048-bit RSA keys for all certificates
- SHA-256 hashing algorithm
- 10-year validity period by default
- Proper key usage extensions for server/client certificates

### Key Derivation

- PBKDF2 key derivation function with SHA-256
- Deterministic seed-based generation for reproducibility
- Secure random seed generation when not provided

## Generated Configuration Details

### Server Configuration

- Subnet topology with 10.15.0.0/24 network
- DNS push to clients (Google DNS 8.8.8.8 and Cloudflare 1.1.1.1)
- Gateway redirect for full VPN tunnel
- Optimized MTU settings (1400/1320)
- Keepalive 10/60 for connection monitoring

### Client Configuration

- AES-256-GCM encryption
- SHA-256 authentication
- Server certificate verification
- Persistent connection settings

## Notes

- The `secrets/` directory contains sensitive cryptographic material. Keep it secure and do not share it.
- Client configurations are standalone files that can be imported directly into OpenVPN clients.
- The server configuration expects the TLS-crypt-v2 key to be in the `secrets/` directory.
- Rerunning the generator will reuse existing CA and DH parameters if found, ensuring consistency.

## License

This project is available for use under standard open-source practices. Please check with the repository owner for specific licensing terms.
