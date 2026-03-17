# uPKI

A modern PKI (Public Key Infrastructure) management system built in Python.

## Badges

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
[![Repository](https://img.shields.io/badge/Repository-GitHub-blue)](https://github.com/circle-rd/upki)

## Overview

uPKI is a lightweight, modern PKI management system that provides a simple yet powerful way to manage certificates, keys, and public key infrastructure. It supports both file-based and MongoDB storage backends, with ZeroMQ-based communication for Registration Authority (RA) interactions.

## Project Structure

```
📂 upkica/
├── 📂 ca/
│   ├── authority.py
│   ├── certRequest.py
│   ├── privateKey.py
│   └── publicCert.py
├── 📂 connectors/
│   ├── listener.py
│   ├── zmqListener.py
│   └── zmqRegister.py
├── 📂 core/
│   ├── common.py
│   ├── options.py
│   ├── upkiError.py
│   └── upkiLogger.py
├── 📂 data/
│   ├── admin.yml
│   ├── ca.yml
│   ├── ra.yml
│   ├── server.yml
│   └── user.yml
├── 📂 storage/
│   ├── abstractStorage.py
│   ├── fileStorage.py
│   └── mongoStorage.py
└── 📂 utils/
    ├── admins.py
    ├── config.py
    └── profiles.py
```

## Main Components

### CA (Certificate Authority)

The core PKI implementation handling certificate issuance, key management, and certificate requests. Includes classes for managing private keys, public certificates, and certificate signing requests.

### Connectors

ZeroMQ-based communication modules that enable interaction between the Certificate Authority and Registration Authorities (RA). Supports both clear-mode registration and TLS-encrypted listening.

### Core

Essential utilities including:

- **upkiLogger**: Logging system with colored console output and file rotation
- **upkiError**: Custom exception handling
- **options**: Configuration management
- **common**: Shared utilities and helpers

### Storage

Abstraction layer for certificate and key storage with support for:

- **fileStorage**: File-based storage backend
- **mongoStorage**: MongoDB-based storage backend

### Utils

Administrative tools and configuration management including admin user management, configuration loading, and certificate profiles.

## Installation

```bash
pip install -r requirements.txt
python setup.py install
```

## Quick Start

```bash
# Initialize the PKI
python ca_server.py init

# Register the RA (clear-mode)
python ca_server.py register

# Start the CA server (TLS mode)
python ca_server.py listen
```

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**Author**: CIRCLE Cyber  
**Contact**: contact@circle-cyber.com  
**Version**: 2.0.0
