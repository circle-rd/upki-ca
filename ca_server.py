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
import getpass
import os
import secrets
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

    def _config_path(self) -> str | None:
        """Derive the config file path from the storage path when one is set."""
        if self._storage_path:
            return os.path.join(self._storage_path, "ca.config.yml")
        return None

    def initialize(self) -> bool:
        """
        Initialize the CA Server.

        Returns:
            bool: True if successful
        """
        try:
            # Load configuration
            self._config = Config(self._config_path())
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

    def init_pki(
        self,
        ca_key_path: str | None = None,
        ca_cert_path: str | None = None,
        ca_password: bytes | None = None,
    ) -> bool:
        """
        Initialize the PKI infrastructure.

        Args:
            ca_key_path: Path to an existing CA private key (PEM) to import.
            ca_cert_path: Path to an existing CA certificate (PEM) to import.
            ca_password: Optional password to decrypt the imported CA private key.

        Returns:
            bool: True if successful
        """
        try:
            self._logger.info("Initializing PKI...")

            # Load configuration (create defaults if absent)
            if self._config is None:
                self._config = Config(self._config_path())
                self._config.load()

            # Auto-generate a secure registration seed when none is configured
            if not self._config.get_seed():
                seed = secrets.token_urlsafe(32)
                self._config.set_seed(seed)
                print("-" * 60)
                print("  Registration seed generated (transmit securely to the RA):")
                print(f"  {seed}")
                print("-" * 60)
                self._logger.info(
                    "Registration seed auto-generated and saved to config"
                )

            # Initialize storage
            storage = FileStorage(self._storage_path)
            storage.initialize()

            # Initialize Authority (generates a new CA or imports an existing one)
            self._authority = Authority.get_instance()
            self._authority.initialize(
                storage=storage,
                import_key=ca_key_path,
                import_cert=ca_cert_path,
                import_password=ca_password,
            )

            # Save configuration
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
            self._config = Config(self._config_path())
            self._config.load()

            # Get host and port
            host = self._config.get_host()
            port = self._config.get_port() + 1  # Use port + 1 for registration
            seed = self._config.get_seed()

            # Display the seed prominently so the operator can provide it to the RA
            print("-" * 60)
            if not seed:
                seed = "default_seed"
                self._logger.warning(
                    "No seed configured – falling back to insecure 'default_seed'"
                )
                print("  WARNING: No seed configured in ca.config.yml.")
                print(
                    "  Using insecure fallback 'default_seed'. Run 'init' first or set"
                )
                print(
                    "  the 'seed' key in ca.config.yml before deploying in production."
                )
            else:
                print("  Registration seed (provide this value to the RA operator):")
                print(f"  {seed}")
            print("-" * 60)
            self._logger.info("Registration listener seed configured")

            # Initialize storage and Authority so that _register_node() can generate
            # the RA certificate during the registration handshake.
            storage = FileStorage(self._storage_path)
            storage.initialize()
            self._authority = Authority.get_instance()
            self._authority.initialize(storage=storage)

            # Create registration listener
            self._register_listener = ZMQRegister(
                host=host, port=port, seed=seed, authority=self._authority
            )

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

    parser.add_argument(
        "--path", default=None, help="Base path for storage (default: ~/.upki/ca)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # init command
    init_parser = subparsers.add_parser("init", help="Initialize PKI")
    init_parser.add_argument(
        "--ca-key",
        dest="ca_key",
        default=None,
        metavar="PATH",
        help="Path to an existing CA private key (PEM) to import instead of generating a new CA",
    )
    init_parser.add_argument(
        "--ca-cert",
        dest="ca_cert",
        default=None,
        metavar="PATH",
        help="Path to an existing CA certificate (PEM) to import",
    )
    ca_pwd_group = init_parser.add_mutually_exclusive_group()
    ca_pwd_group.add_argument(
        "--ca-password",
        dest="ca_password",
        default=None,
        metavar="PASSWORD",
        help="Password for the CA private key (prefer --ca-password-file for safer input)",
    )
    ca_pwd_group.add_argument(
        "--ca-password-file",
        dest="ca_password_file",
        default=None,
        metavar="PATH",
        help="Path to a file containing the CA private key password",
    )

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
        # Validate that --ca-key and --ca-cert are always specified together
        ca_key = getattr(args, "ca_key", None)
        ca_cert = getattr(args, "ca_cert", None)
        if bool(ca_key) != bool(ca_cert):
            print(
                "Error: --ca-key and --ca-cert must always be specified together.",
                file=sys.stderr,
            )
            return 1

        ca_password: bytes | None = None
        if ca_key:
            ca_password_arg = getattr(args, "ca_password", None)
            ca_password_file = getattr(args, "ca_password_file", None)
            if ca_password_arg is not None:
                # An empty string means the key is not encrypted
                ca_password = (
                    ca_password_arg.encode("utf-8") if ca_password_arg else None
                )
            elif ca_password_file is not None:
                try:
                    with open(ca_password_file) as f:
                        raw = f.read().strip()
                    ca_password = raw.encode("utf-8") if raw else None
                except OSError as e:
                    print(f"Error: Cannot read password file: {e}", file=sys.stderr)
                    return 1
            else:
                # Prompt interactively; empty input means the key is not encrypted
                raw = getpass.getpass(
                    "CA private key password (press Enter if unencrypted): "
                )
                ca_password = raw.encode("utf-8") if raw else None

        if server.init_pki(
            ca_key_path=ca_key, ca_cert_path=ca_cert, ca_password=ca_password
        ):
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
