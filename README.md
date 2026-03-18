# uPKI CA Server

Certificate Authority for PKI operations.

## Installation

```bash
pip install upkica
```

## Quick Start

```bash
# Initialize PKI
python ca_server.py init

# Register RA (clear mode)
python ca_server.py register

# Start CA server (TLS mode)
python ca_server.py listen
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=upkica
```

## Project Structure

```
upkica/
├── ca/                  # Core CA classes
│   ├── authority.py     # Main CA class
│   ├── certRequest.py   # CSR handler
│   ├── privateKey.py    # Private key handler
│   └── publicCert.py    # Certificate handler
├── connectors/          # ZMQ connectors
│   ├── listener.py      # Base listener
│   ├── zmqListener.py   # CA operations
│   └── zmqRegister.py   # RA registration
├── core/               # Core utilities
│   ├── common.py       # Base utilities
│   ├── options.py      # Allowed values
│   ├── upkiError.py   # Exceptions
│   ├── upkiLogger.py  # Logging
│   └── validators.py   # Input validation
├── storage/           # Storage backends
│   ├── abstractStorage.py # Storage interface
│   ├── fileStorage.py    # File-based backend
│   └── mongoStorage.py   # MongoDB backend (stub)
└── utils/            # Utility modules
    ├── admins.py     # Admin management
    ├── config.py     # Configuration
    └── profiles.py   # Profile management
```

## License

MIT
