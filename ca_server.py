#!/usr/bin/env python3
"""
uPKI CA Server - Command Line Interface

This module provides the CLI entry point for the uPKI CA Server.

Usage:
    python ca_server.py init              # Initialize PKI
    python ca_server.py register         # Register RA (clear mode)
    python ca_server.py listen           # Start CA server (TLS mode)

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import argparse
import signal
import sys

from upki_ca.ca.authority import Authority
from upki_ca.connectors.zmq_listener import ZMQListener
from upki_ca.connectors.zmq_register import ZMQRegister
from upki_ca.core.common import Common
from upki_ca.core.upki_logger import UpkiLogger
from upki_ca.storage.file_storage import FileStorage
from upki_ca.utils.config import Config


class CAServer(Common):
    """
    Main CA Server class.
    """

    def __init__(self) -> None:
        """Initialize CA Server."""
        self._authority: Authority | None = None
        self._listener: ZMQListener | None = None
        self._register_listener: ZMQRegister | None = None
        self._config: Config | None = None
        self._logger = UpkiLogger.get_logger("ca_server")
        self._storage_path: str | None = None

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals."""
        self._logger.info("Shutting down...")
        self.stop()
        sys.exit(0)

    def initialize(self) -> bool:
        """
        Initialize the CA Server.

        Returns:
            bool: True if successful
        """
        try:
            # Load configuration
            self._config = Config()
            self._config.load()

            # Initialize storage
            storage = FileStorage(self._storage_path)
            storage.initialize()

            # Initialize Authority
            self._authority = Authority.get_instance()
            self._authority.initialize(storage=storage)

            return True
        except Exception as e:
            self._logger.error("CA Server", e)
            return False

    def init_pki(self) -> bool:
        """
        Initialize the PKI infrastructure.

        Returns:
            bool: True if successful
        """
        try:
            self._logger.info("Initializing PKI...")

            # Initialize storage
            storage = FileStorage(self._storage_path)
            storage.initialize()

            # Initialize Authority (generates CA if not exists)
            self._authority = Authority.get_instance()
            self._authority.initialize(storage=storage)

            # Save configuration
            if self._config:
                self._config.save()

            self._logger.info("PKI initialized successfully")
            return True
        except Exception as e:
            self._logger.error("CA Server", e)
            return False

    def register(self) -> bool:
        """
        Start the registration listener (clear mode).

        Returns:
            bool: True if successful
        """
        try:
            self._logger.info("Starting registration listener...")

            # Load configuration
            self._config = Config()
            self._config.load()

            # Get host and port
            host = self._config.get_host()
            port = self._config.get_port() + 1  # Use port + 1 for registration
            seed = self._config.get_seed() or "default_seed"

            # Create registration listener
            self._register_listener = ZMQRegister(host=host, port=port, seed=seed)

            self._register_listener.initialize()
            self._register_listener.bind()
            self._register_listener.start()

            self._logger.info(f"Registration listener started on {host}:{port}")

            # Keep running
            while True:
                pass

        except Exception as e:
            self._logger.error("CA Server", e)
            return False

    def listen(self) -> bool:
        """
        Start the CA listener (TLS mode).

        Returns:
            bool: True if successful
        """
        try:
            self._logger.info("Starting CA server...")

            # Initialize
            if not self.initialize():
                return False

            # Get host and port
            host = self._config.get_host() if self._config else "127.0.0.1"
            port = self._config.get_port() if self._config else 5000

            # Get storage
            storage = self._authority.storage if self._authority else None

            # Create listener
            self._listener = ZMQListener(host=host, port=port, storage=storage)

            self._listener.initialize()
            self._listener.initialize_authority()
            self._listener.bind()
            self._listener.start()

            self._logger.info(f"CA server started on {host}:{port}")

            # Keep running
            while True:
                pass

        except Exception as e:
            self._logger.error("CA Server", e)
            return False

    def stop(self) -> bool:
        """
        Stop the CA Server.

        Returns:
            bool: True if successful
        """
        try:
            if self._listener:
                self._listener.stop()

            if self._register_listener:
                self._register_listener.stop()

            self._logger.info("CA server stopped")
            return True
        except Exception as e:
            self._logger.error("CA Server", e)
            return False


def main() -> int:
    """
    Main entry point.

    Returns:
        int: Exit code
    """
    # Parse arguments
    parser = argparse.ArgumentParser(description="uPKI CA Server")

    parser.add_argument("--path", default=None, help="Base path for storage (default: ~/.upki/ca)")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # init command
    subparsers.add_parser("init", help="Initialize PKI")

    # register command
    subparsers.add_parser("register", help="Register RA (clear mode)")

    # listen command
    listen_parser = subparsers.add_parser("listen", help="Start CA server (TLS mode)")
    listen_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    listen_parser.add_argument("--port", type=int, default=5000, help="Port to bind to")

    args = parser.parse_args()

    # Initialize logger
    UpkiLogger.initialize()

    # Create server
    server = CAServer()
    server._storage_path = args.path

    # Execute command
    if args.command == "init":
        if server.init_pki():
            print("PKI initialized successfully")
            return 0
        else:
            print("Failed to initialize PKI", file=sys.stderr)
            return 1

    elif args.command == "register":
        if server.register():
            return 0
        else:
            print("Registration listener failed", file=sys.stderr)
            return 1

    elif args.command == "listen":
        if server.listen():
            return 0
        else:
            print("CA server failed to start", file=sys.stderr)
            return 1

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
