# uPKI CA Server Wiki

Welcome to the uPKI CA Server Wiki. This page provides comprehensive documentation for understanding, installing, and using the uPKI Certificate Authority system.

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Usage](#usage)
6. [ZMQ Protocol](#zmq-protocol)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)

---

## Introduction

### What is uPKI?

uPKI is a modern Public Key Infrastructure (PKI) implementation designed for scalable certificate lifecycle management. It provides a complete Certificate Authority (CA) solution with support for:

- Certificate generation and signing
- Certificate revocation
- Certificate Revocation Lists (CRL)
- Online Certificate Status Protocol (OCSP)
- Certificate profiles
- Administrative management

### Key Features

- **ZeroMQ Protocol**: Native ZMQ messaging for reliable, asynchronous CA operations
- **Multi-port Architecture**: Separate ports for CA operations and RA registration
- **Flexible Storage**: File-based storage (default) with MongoDB support
- **Certificate Profiles**: Define and enforce certificate templates
- **Production Ready**: Docker deployment support

### Requirements

| Component    | Requirement                       |
| ------------ | --------------------------------- |
| Python       | 3.11+                             |
| Dependencies | cryptography, pyyaml, tinydb, zmq |
| RAM          | 512MB minimum                     |
| Disk         | 1GB minimum (for certificates)    |

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Clients                               │
│  (RA Servers, Certificate Requests, Admin Tools)           │
└───────────────────────┬─────────────────────────────────────┘
                        │ ZMQ
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
   ┌─────────┐                    ┌─────────┐
   │ Port    │                    │ Port    │
   │ 5000    │                    │ 5001    │
   │ (CA)    │                    │ (RA)    │
   └────┬────┘                    └────┬────┘
        │                              │
        └──────────────┬───────────────┘
                       │
                       ▼
            ┌─────────────────────┐
            │   uPKI CA Server    │
            ├─────────────────────┤
            │  Certificate Store  │
            │  (File/MongoDB)     │
            └─────────────────────┘
```

### Components

#### Certificate Authority (CA)

The core CA component handles:

- Root CA management
- Intermediate CA operations
- Certificate signing
- Certificate revocation
- CRL generation
- OCSP responses

#### ZMQ Connectors

Two ZMQ listeners handle different operations:

1. **CA Operations (Port 5000)**
   - Certificate signing
   - Certificate revocation
   - CRL generation
   - OCSP queries

2. **RA Registration (Port 5001)**
   - Registration Authority enrollment
   - RA authentication

#### Storage Backend

- **File Storage**: Default storage using JSON files
- **MongoDB Storage**: Alternative using MongoDB (stub implementation)

---

## Installation

### From PyPI

```bash
pip install upki-ca
```

### From Source

```bash
git clone https://github.com/circle-rd/upki.git
cd upki
pip install -e .
```

### Docker Installation

```bash
# Pull the image
docker pull upki-ca/ca-server:latest

# Run the container
docker run -d \
  --name upki-ca \
  -p 5000:5000 \
  -p 5001:5001 \
  -v upki_data:/data \
  upki-ca/ca-server:latest
```

### Development Setup

```bash
# Clone and install with dev dependencies
git clone https://github.com/circle-rd/upki.git
cd upki
pip install -e ".[dev]"

# Run tests
pytest
```

---

## Configuration

### Configuration File

The default configuration file is created on first run. You can customize it:

```yaml
# uPKI Configuration
ca:
  name: "uPKI Root CA"
  country: "US"
  organization: "Example Corp"
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

logging:
  level: "INFO"
  file: "./logs/upki.log"
```

### Configuration Options

#### CA Settings

| Option           | Description          | Default        |
| ---------------- | -------------------- | -------------- |
| `name`           | CA common name       | "uPKI Root CA" |
| `country`        | Country code         | "US"           |
| `organization`   | Organization name    | -              |
| `validity_days`  | Certificate validity | 3650           |
| `key_type`       | Key type (RSA/ECDSA) | "RSA"          |
| `key_size`       | Key size in bits     | 4096           |
| `hash_algorithm` | Hash algorithm       | "sha256"       |

#### Server Settings

| Option    | Description          | Default   |
| --------- | -------------------- | --------- |
| `host`    | Bind address         | "0.0.0.0" |
| `ca_port` | CA operations port   | 5000      |
| `ra_port` | RA registration port | 5001      |

#### Storage Settings

| Option | Description     | Default  |
| ------ | --------------- | -------- |
| `type` | Storage backend | "file"   |
| `path` | Data directory  | "./data" |

---

## Usage

### Initial Setup

#### 1. Initialize the PKI

```bash
python ca_server.py init
```

This creates:

- Root CA certificate
- Private key (encrypted)
- Configuration files

#### 2. Register an RA

```bash
python ca_server.py register
```

#### 3. Start the Server

```bash
# Start in background
python ca_server.py listen &

# Or with custom config
python ca_server.py listen --config /path/to/config.yaml
```

### ZMQ Client Example

```python
import zmq
import json

context = zmq.Context()

# Connect to CA operations
ca_socket = context.socket(zmq.REQ)
ca_socket.connect("tcp://localhost:5000")

# Sign a certificate
request = {
    "action": "sign",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "profile": "server"
}
ca_socket.send(json.dumps(request))
response = ca_socket.recv()
```

---

## ZMQ Protocol

### Message Format

All ZMQ messages use JSON format:

```json
{
  "action": "action_name",
  "data": { ... }
}
```

### Available Actions

| Action     | Port | Description          |
| ---------- | ---- | -------------------- |
| `sign`     | 5000 | Sign a certificate   |
| `revoke`   | 5000 | Revoke a certificate |
| `crl`      | 5000 | Generate CRL         |
| `ocsp`     | 5000 | Query OCSP           |
| `register` | 5001 | Register an RA       |
| `info`     | 5000 | Get CA info          |

### Response Format

```json
{
  "status": "success",
  "data": { ... },
  "message": "Optional message"
}
```

For detailed protocol specifications, see [CA_ZMQ_PROTOCOL.md](docs/CA_ZMQ_PROTOCOL.md).

---

## Security Considerations

### Private Key Protection

- Private keys are encrypted at rest
- Use strong passphrases
- Rotate keys regularly

### Network Security

- Use TLS for production deployments
- Restrict access to CA ports
- Use firewalls

### Certificate Profiles

Define strict profiles to enforce:

- Key sizes
- Validity periods
- Key usage extensions
- Extended key usage

### Audit Logging

Enable comprehensive logging for:

- Certificate operations
- Administrative actions
- Failed attempts

---

## Troubleshooting

### Common Issues

#### Server Won't Start

1. Check if ports are available:

   ```bash
   lsof -i :5000
   lsof -i :5001
   ```

2. Check configuration syntax:
   ```bash
   python -c "import yaml; yaml.safe_load(open('config.yaml'))"
   ```

#### ZMQ Connection Errors

1. Verify server is running:

   ```bash
   ps aux | grep ca_server
   ```

2. Check firewall rules

#### Certificate Validation Failures

1. Verify CA certificate is trusted
2. Check certificate chain
3. Verify OCSP responder

### Logging

Enable debug logging:

```yaml
logging:
  level: "DEBUG"
  file: "./logs/debug.log"
```

### Getting Help

- Check [GitHub Issues](https://github.com/circle-rd/upki/issues)
- Review [Documentation](docs/)
- Open a new issue for bugs

---

## API Reference

### Command Line Interface

#### init

Initialize a new PKI:

```bash
python ca_server.py init [--config CONFIG]
```

#### register

Register an RA:

```bash
python ca_server.py register [--config CONFIG]
```

#### listen

Start the CA server:

```bash
python ca_server.py listen [--config CONFIG] [--host HOST]
```

### Python API

#### CertificateAuthority

```python
from upki_ca.ca.authority import CertificateAuthority

ca = CertificateAuthority()
ca.initialize()
ca.sign(csr)
ca.revoke(cert_serial)
ca.generate_crl()
```

#### Certificate Profiles

```python
from upki_ca.utils.profiles import ProfileManager

profiles = ProfileManager()
profiles.load()
profile = profiles.get("server")
```

---

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
