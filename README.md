# uPKI CA Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Python Version](https://img.shields.io/pypi/pyversions/upki-ca)](https://pypi.org/project/upki-ca/)
[![Docker Image](https://img.shields.io/docker/v/upki-ca/ca-server?label=docker)](https://hub.docker.com/r/upki-ca/ca-server)

A production-ready Public Key Infrastructure (PKI) and Certificate Authority system with native ZeroMQ protocol support for secure, high-performance certificate operations.

## Overview

uPKI CA Server is a modern PKI implementation designed for scalable certificate lifecycle management. It provides a complete Certificate Authority solution with support for certificate generation, signing, revocation, CRL management, OCSP responses, certificate profiles, and administrative management.

Built on ZeroMQ (ZMQ) for reliable, asynchronous communication, uPKI offers two dedicated ports:

- **Port 5000**: CA operations (certificate signing, revocation, CRL generation, OCSP)
- **Port 5001**: RA (Registration Authority) registration endpoint

## Key Features

- **Certificate Authority Operations** — Generate Root CA and Intermediate CA certificates with full PKI hierarchy support
- **Certificate Signing** — Process Certificate Signing Requests (CSRs) with configurable key types and algorithms
- **Revocation Management** — Revoke certificates and generate Certificate Revocation Lists (CRL)
- **OCSP Support** — Built-in Online Certificate Status Protocol responder for real-time certificate validation
- **Certificate Profiles** — Define and enforce certificate templates with custom extensions, key usage, and validity periods
- **Administrative Management** — Manage CA administrators with role-based access control
- **ZMQ Protocol** — Native ZeroMQ messaging for reliable, asynchronous CA operations
- **Multiple Storage Backends** — File-based storage (default) and MongoDB support
- **Docker Deployment** — Production-ready Docker image for easy containerized deployment

## Requirements

- **Python**: 3.11 or higher
- **Dependencies**:
  - `cryptography` — cryptographic operations
  - `pyyaml` — configuration management
  - `tinydb` — embedded document database
  - `zmq` — ZeroMQ messaging

## Installation

### From PyPI

```bash
pip install upki-ca
```

### From Source

```bash
# Clone the repository
git clone https://github.com/circle-rd/upki.git
cd upki

# Install dependencies
pip install -e .
```

### Development Installation

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run the test suite
pytest

# Run with coverage report
pytest --cov=upki_ca --cov-report=html
```

## Quick Start

### 1. Initialize the PKI

```bash
python ca_server.py init
```

This creates the Root CA with default configuration. You can customize the CA by editing the configuration file.

### 2. Register a Registration Authority (RA)

```bash
# Register an RA in clear mode (for initial setup)
python ca_server.py register
```

### 3. Start the CA Server

```bash
# Start the CA server in TLS mode
python ca_server.py listen
```

The server will start listening on:

- `tcp://*:5000` — CA operations
- `tcp://*:5001` — RA registration

## Configuration

The CA server uses a YAML configuration file. On first run, it creates a default configuration. Key configuration options include:

```yaml
ca:
  name: "uPKI Root CA"
  validity_days: 3650
  key_type: "RSA"
  key_size: 4096
  hash_algorithm: "sha256"

server:
  host: "0.0.0.0"
  ca_port: 5000
  ra_port: 5001

storage:
  type: "file"
  path: "./data"
```

## Usage Examples

### Initialize a New CA

```bash
python ca_server.py init --config custom_config.yaml
```

### Start the Server

```bash
# Start with default settings
python ca_server.py listen

# Start on specific host
python ca_server.py listen --host 127.0.0.1
```

### ZMQ Client Operations

Connect to the CA server using ZMQ to perform operations:

```python
import zmq

# CA operations port (5000)
context = zmq.Context()
ca_socket = context.socket(zmq.REQ)
ca_socket.connect("tcp://localhost:5000")

# RA registration port (5001)
ra_socket = context.socket(zmq.REQ)
ra_socket.connect("tcp://localhost:5001")
```

For detailed protocol specifications, see [`docs/CA_ZMQ_PROTOCOL.md`](docs/CA_ZMQ_PROTOCOL.md).

## Deployment

### Docker Deployment

#### Using Docker Run

```bash
docker run -d \
  --name upki-ca \
  -p 5000:5000 \
  -p 5001:5001 \
  -v upki_data:/data \
  upki-ca/ca-server:latest
```

#### Using Docker Compose

```yaml
version: "3.8"

services:
  upki-ca:
    image: upki-ca/ca-server:latest
    ports:
      - "5000:5000"
      - "5001:5001"
    volumes:
      - upki_data:/data
    restart: unless-stopped
```

#### Build from Source

```bash
docker build -t upki-ca/ca-server:latest .
```

### Direct Deployment

```bash
# Install and run as a service
pip install upki-ca
python ca_server.py init
python ca_server.py listen
```

For production deployments, consider:

- Running behind a reverse proxy (nginx, Traefik)
- Enabling TLS for all connections
- Using a proper certificate for the CA
- Setting up monitoring and logging

## Project Organization

```
upki/
├── 📁 .github/              # GitHub workflows and actions
│   └── workflows/           # CI/CD pipelines
├── 📁 docs/                 # Documentation
│   ├── CA_ZMQ_PROTOCOL.md   # ZMQ protocol specification
│   └── SPECIFICATIONS_CA.md # CA specifications
├── 📁 tests/                # Test suite
│   └── test_*.py           # Unit and functional tests
├── 📁 upki_ca/               # Main package
│   ├── 📁 ca/              # Certificate Authority core
│   │   ├── authority.py    # CA implementation
│   │   ├── cert_request.py  # CSR handling
│   │   ├── private_key.py   # Private key operations
│   │   └── public_cert.py   # Certificate handling
│   ├── 📁 connectors/      # ZMQ connectors
│   │   ├── listener.py     # Base listener
│   │   ├── zmq_listener.py  # CA operations listener
│   │   └── zmq_register.py # RA registration
│   ├── 📁 core/            # Core utilities
│   │   ├── common.py       # Common utilities
│   │   ├── options.py      # Configuration options
│   │   ├── upki_error.py   # Custom exceptions
│   │   ├── upki_logger.py  # Logging utilities
│   │   └── validators.py  # Input validators
│   ├── 📁 storage/         # Storage backends
│   │   ├── abstract_storage.py # Storage interface
│   │   ├── file_storage.py  # File-based storage
│   │   └── mongo_storage.py # MongoDB storage
│   └── 📁 utils/           # Utility modules
│       ├── config.py       # Configuration management
│       └── profiles.py     # Certificate profiles
├── 📄 pyproject.toml       # Project configuration
├── 📄 Dockerfile           # Docker image definition
└── 📄 ca_server.py          # Main entry point
```

## Documentation

- [ZMQ Protocol Specification](docs/CA_ZMQ_PROTOCOL.md) — Detailed protocol documentation
- [CA Specifications](docs/SPECIFICATIONS_CA.md) — Technical specifications

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting pull requests.
