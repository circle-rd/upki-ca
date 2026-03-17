# -*- coding:utf-8 -*-

"""
Certificate Authority management for uPKI.

This module provides the Authority class which handles all PKI operations
including CA keychain generation/import, certificate issuance, and RA registration.
"""

import os
import sys
import time
import hashlib
import threading
from typing import Any

import validators
from cryptography import x509

import upkica
from upkica.core.common import Common
from upkica.core.upkiLogger import UpkiLogger


class Authority(Common):
    """Certificate Authority management class.

    Handles all PKI operations including CA initialization, keychain generation
    or import, certificate signing, and RA registration server management.

    Attributes:
        _config: Configuration object.
        _profiles: Profiles utility instance.
        _admins: Admins utility instance.
        _private: PrivateKey handler.
        _request: CertRequest handler.
        _public: PublicCert handler.
        _storage: Storage backend (set after load).

    Args:
        config: Configuration object with logger and storage settings.

    Example:
        >>> authority = Authority(config)
        >>> authority.initialize()
    """

    def __init__(self, config: Any) -> None:
        """Initialize Authority with configuration.

        Args:
            config: Configuration object containing logger and storage settings.

        Raises:
            UPKIError: If initialization fails.
        """
        try:
            super().__init__(config._logger)
        except Exception as err:
            raise upkica.core.UPKIError(1, err)

        # Initialize handles
        self._config: Any = config
        self._profiles: Any = None
        self._admins: Any = None
        self._private: Any = None
        self._request: Any = None
        self._public: Any = None
        self._storage: Any = None

    def _load_profile(self, name: str) -> dict:
        """Load a certificate profile by name.

        Args:
            name: Name of the profile to load.

        Returns:
            Dictionary containing profile configuration.

        Raises:
            UPKIError: If profile cannot be loaded.
        """
        try:
            data = self._profiles.load(name)
        except Exception as err:
            raise upkica.core.UPKIError(2, f"Unable to load {name} profile: {err}")
        return data

    def initialize(self, keychain: str | None = None) -> bool:
        """Initialize the PKI system.

        Initialize the PKI config file and store it on disk. Initialize
        storage if needed. Generate Private and Public keys for CA.
        Generate Private and Public keys used for 0MQ TLS socket.
        Called on initialization only.

        Args:
            keychain: Optional path to directory containing existing CA files
                     (ca.key, ca.crt) for import.

        Returns:
            True if initialization successful.

        Raises:
            UPKIError: If initialization fails at any step.
        """
        if keychain is not None:
            # No need to initialize anything if CA required files do not exist
            for f in ["ca.key", "ca.crt"]:
                if not os.path.isfile(os.path.join(keychain, f)):
                    raise upkica.core.UPKIError(
                        3, "Missing required CA file for import."
                    )

        try:
            self._config.initialize()
        except upkica.core.UPKIError as err:
            raise upkica.core.UPKIError(err.code, err.reason)
        except Exception as err:
            raise upkica.core.UPKIError(4, f"Unable to setup config: {err}")

        try:
            # Load CA like usual
            self.load()
        except upkica.core.UPKIError as err:
            raise upkica.core.UPKIError(err.code, err.reason)
        except Exception as err:
            raise upkica.core.UPKIError(5, err)

        try:
            # Load CA specific profile
            ca_profile = self._load_profile("ca")
        except Exception as err:
            raise upkica.core.UPKIError(6, err)

        try:
            # Setup private handle
            self._private = upkica.ca.PrivateKey(self._config)
        except Exception as err:
            raise upkica.core.UPKIError(
                7, f"Unable to initialize CA Private Key: {err}"
            )

        try:
            # Setup request handle
            self._request = upkica.ca.CertRequest(self._config)
        except Exception as err:
            raise upkica.core.UPKIError(
                8, f"Unable to initialize CA Certificate Request: {err}"
            )

        try:
            # Setup public handle
            self._public = upkica.ca.PublicCert(self._config)
        except Exception as err:
            raise upkica.core.UPKIError(
                9, f"Unable to initialize CA Public Certificate: {err}"
            )

        if keychain:
            try:
                (pub_cert, priv_key) = self._import_keychain(ca_profile, keychain)
            except upkica.core.UPKIError as err:
                raise upkica.core.UPKIError(err.code, err.reason)
            except Exception as err:
                raise upkica.core.UPKIError(10, err)
        else:
            try:
                (pub_cert, priv_key) = self._create_keychain(ca_profile)
            except upkica.core.UPKIError as err:
                raise upkica.core.UPKIError(err.code, err.reason)
            except Exception as err:
                raise upkica.core.UPKIError(11, err)

        try:
            dn = self._get_dn(pub_cert.subject)
        except Exception as err:
            raise upkica.core.UPKIError(
                12, f"Unable to get DN from CA certificate: {err}"
            )

        try:
            self._storage.certify_node(dn, pub_cert, internal=True)
        except Exception as err:
            raise upkica.core.UPKIError(12, f"Unable to activate CA: {err}")

        try:
            (server_pub, server_priv) = self._create_listener(
                "server", pub_cert, priv_key
            )
        except upkica.core.UPKIError as err:
            raise upkica.core.UPKIError(err.code, err.reason)
        except Exception as err:
            raise upkica.core.UPKIError(13, err)

        try:
            dn = self._get_dn(server_pub.subject)
        except Exception as err:
            raise upkica.core.UPKIError(
                14, f"Unable to get DN from server certificate: {err}"
            )

        try:
            self._storage.certify_node(dn, server_pub, internal=True)
        except Exception as err:
            raise upkica.core.UPKIError(14, f"Unable to activate server: {err}")

        return True

    def _import_keychain(self, profile: dict, ca_path: str) -> tuple:
        """Import existing CA keychain from files.

        Reads existing CA private key, certificate request, and certificate
        from files in the specified directory.

        Args:
            profile: Certificate profile configuration.
            ca_path: Path to directory containing CA files.

        Returns:
            Tuple of (public_certificate, private_key).

        Raises:
            UPKIError: If import fails at any step.
        """
        if not os.path.isdir(ca_path):
            raise upkica.core.UPKIError(15, "Directory does not exist")

        # Load private key data
        with open(os.path.join(ca_path, "ca.key"), "rb") as key_path:
            self.output("1. CA private key loaded", color="green")
            key_pem = key_path.read()

        try:
            # Load certificate request data
            with open(os.path.join(ca_path, "ca.csr"), "rb") as csr_path:
                self.output("2. CA certificate request loaded", color="green")
                csr_pem = csr_path.read()
        except Exception:
            # If Certificate Request does not exist, create one
            csr_pem = None

        try:
            # Load private key object
            priv_key = self._private.load(key_pem)
            self._storage.store_key(
                self._private.dump(priv_key, password=self._config.password),
                nodename="ca",
            )
        except Exception as err:
            raise upkica.core.UPKIError(16, err)

        # If CSR is invalid or does not exist, just create one
        if csr_pem is None:
            try:
                csr = self._request.generate(priv_key, "CA", profile)
                csr_pem = self._request.dump(csr)
                self.output("2. CA certificate request generated", color="green")
            except Exception as err:
                raise upkica.core.UPKIError(17, err)

        try:
            # Load certificate request object
            csr = self._request.load(csr_pem)
            self._storage.store_request(self._request.dump(csr), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(18, err)

        # Load public certificate data
        with open(os.path.join(ca_path, "ca.crt"), "rb") as pub_path:
            self.output("3. CA certificate loaded", color="green")
            pub_pem = pub_path.read()

        try:
            # Load public certificate object
            pub_cert = self._public.load(pub_pem)
            self._storage.store_public(self._public.dump(pub_cert), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(19, err)

        return (pub_cert, priv_key)

    def _create_keychain(self, profile: dict) -> tuple:
        """Generate new CA keychain.

        Generates new CA private key, certificate request, and self-signed
        certificate.

        Args:
            profile: Certificate profile configuration.

        Returns:
            Tuple of (public_certificate, private_key).

        Raises:
            UPKIError: If keychain generation fails at any step.
        """
        try:
            priv_key = self._private.generate(profile)
        except Exception as err:
            raise upkica.core.UPKIError(20, f"Unable to generate CA Private Key: {err}")

        try:
            self.output("1. CA private key generated", color="green")
            self.output(self._private.dump(priv_key), level="DEBUG")
            self._storage.store_key(
                self._private.dump(priv_key, password=self._config.password),
                nodename="ca",
            )
        except Exception as err:
            raise upkica.core.UPKIError(21, f"Unable to store CA Private key: {err}")

        try:
            cert_req = self._request.generate(priv_key, "CA", profile)
        except Exception as err:
            raise upkica.core.UPKIError(
                22, f"Unable to generate CA Certificate Request: {err}"
            )

        try:
            self.output("2. CA certificate request generated", color="green")
            self.output(self._request.dump(cert_req), level="DEBUG")
            self._storage.store_request(self._request.dump(cert_req), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(
                23, f"Unable to store CA Certificate Request: {err}"
            )

        try:
            pub_cert = self._public.generate(
                cert_req, None, priv_key, profile, ca=True, selfSigned=True
            )
        except Exception as err:
            raise upkica.core.UPKIError(
                24, f"Unable to generate CA Public Certificate: {err}"
            )

        try:
            self.output("3. CA public certificate generated", color="green")
            self.output(self._public.dump(pub_cert), level="DEBUG")
            self._storage.store_public(self._public.dump(pub_cert), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(
                25, f"Unable to store CA Public Certificate: {err}"
            )

        return (pub_cert, priv_key)

    def _create_listener(self, profile: str, pub_cert: Any, priv_key: Any) -> tuple:
        """Generate listener keychain for 0MQ TLS.

        Creates a separate keychain for the CA server's TLS listener.

        Args:
            profile: Profile name to use.
            pub_cert: CA public certificate.
            priv_key: CA private key.

        Returns:
            Tuple of (server_public_certificate, server_private_key).

        Raises:
            UPKIError: If keychain generation fails at any step.
        """
        try:
            # Load Server specific profile
            server_profile = self._load_profile(profile)
        except Exception as err:
            raise upkica.core.UPKIError(26, err)

        try:
            server_priv_key = self._private.generate(server_profile)
        except Exception as err:
            raise upkica.core.UPKIError(
                27, f"Unable to generate Server Private Key: {err}"
            )

        try:
            self.output("4. Server private key generated", color="green")
            self.output(self._private.dump(server_priv_key), level="DEBUG")
            self._storage.store_key(self._private.dump(server_priv_key), nodename="zmq")
        except Exception as err:
            raise upkica.core.UPKIError(
                28, f"Unable to store Server Private key: {err}"
            )

        try:
            server_cert_req = self._request.generate(
                server_priv_key, "ca", server_profile
            )
        except Exception as err:
            raise upkica.core.UPKIError(
                29, f"Unable to generate Server Certificate Request: {err}"
            )

        try:
            self.output("5. Server certificate request generated", color="green")
            self.output(self._request.dump(server_cert_req), level="DEBUG")
            self._storage.store_request(
                self._request.dump(server_cert_req), nodename="zmq"
            )
        except Exception as err:
            raise upkica.core.UPKIError(
                30, f"Unable to store Server Certificate Request: {err}"
            )

        try:
            server_pub_cert = self._public.generate(
                server_cert_req, pub_cert, priv_key, server_profile
            )
        except Exception as err:
            raise upkica.core.UPKIError(
                31, f"Unable to generate Server Public Certificate: {err}"
            )

        try:
            self.output("6. Server public certificate generated", color="green")
            self.output(self._public.dump(server_pub_cert), level="DEBUG")
            self._storage.store_public(
                self._public.dump(server_pub_cert), nodename="zmq"
            )
        except Exception as err:
            raise upkica.core.UPKIError(
                32, f"Unable to store Server Public Certificate: {err}"
            )

        return (server_pub_cert, server_priv_key)

    def load(self) -> bool:
        """Load configuration and connect to storage.

        Loads the config file and connects to the configured storage backend.
        Initializes profiles and admins utilities.

        Returns:
            True if loading successful.

        Raises:
            UPKIError: If config file doesn't exist or loading fails.
        """
        if not os.path.isfile(self._config._path):
            raise upkica.core.UPKIError(
                33,
                f"uPKI is not yet initialized. PLEASE RUN: '{sys.argv[0]} init'",
            )

        try:
            self.output("Loading config...", level="DEBUG")
            self._config.load()
        except Exception as err:
            raise upkica.core.UPKIError(34, f"Unable to load configuration: {err}")

        try:
            self.output("Connecting storage...", level="DEBUG")
            self._storage = self._config.storage
            self._storage.connect()
        except Exception as err:
            raise upkica.core.UPKIError(35, f"Unable to connect to db: {err}")

        # Setup connectors
        self._profiles = upkica.utils.Profiles(self._logger, self._storage)
        self._admins = upkica.utils.Admins(self._logger, self._storage)

        return True

    def register(self, ip: str, port: int) -> bool:
        """Start the registration server process.

        Allow a new RA to get its certificate based on seed value.
        Starts a ZMQ register server on the specified IP and port.

        Args:
            ip: IP address to listen on.
            port: Port number to listen on.

        Returns:
            True when server shuts down.

        Raises:
            UPKIError: If setup fails.
            SystemExit: On keyboard interrupt.
        """
        try:
            # Register seed value
            seed = f"seed:{x509.random_serial_number()}"
            self._config._seed = hashlib.sha1(seed.encode("utf-8")).hexdigest()
        except Exception as err:
            raise upkica.core.UPKIError(36, f"Unable to generate seed: {err}")

        if not validators.ipv4(ip):
            raise upkica.core.UPKIError(37, "Invalid listening IP")
        if not validators.between(int(port), 1024, 65535):
            raise upkica.core.UPKIError(38, "Invalid listening port")

        # Update config
        self._config._host = ip
        self._config._port = port

        try:
            # Setup listeners
            register = upkica.connectors.ZMQRegister(
                self._config, self._storage, self._profiles, self._admins
            )
        except Exception as err:
            raise upkica.core.UPKIError(39, f"Unable to initialize register: {err}")

        cmd = "./ra_server.py"
        if self._config._host != "127.0.0.1":
            cmd += f" --ip {self._config._host}"
        if self._config._port != 5000:
            cmd += f" --port {self._config._port}"
        cmd += f" register --seed {seed.split('seed:', 1)[1]}"

        try:
            t1 = threading.Thread(
                target=register.run,
                args=(
                    ip,
                    port,
                ),
                kwargs={"register": True},
                name="uPKI CA listener",
            )
            t1.daemon = True
            t1.start()

            self.output(
                "Download the upki-ra project on your RA server (the one facing Internet)",
                light=True,
            )
            self.output(
                "Project at: https://github.com/proh4cktive/upki-ra", light=True
            )
            self.output(
                f"Install it, then start your RA with command: \n{cmd}",
                light=True,
            )
            # Stay here to catch Keyboard interrupt
            t1.join()
        except (KeyboardInterrupt, SystemExit):
            self.output("Quitting...", color="red")
            self.output("Bye", color="red")
            raise SystemExit()

        return True

    def listen(self, ip: str, port: int) -> bool:
        """Start the certificate listener server.

        Starts a ZMQ listener server to handle certificate requests.

        Args:
            ip: IP address to listen on.
            port: Port number to listen on.

        Returns:
            True when server shuts down.

        Raises:
            UPKIError: If setup fails.
            SystemExit: On keyboard interrupt.
        """
        if not validators.ipv4(ip):
            raise upkica.core.UPKIError(40, "Invalid listening IP")
        if not validators.between(int(port), 1024, 65535):
            raise upkica.core.UPKIError(41, "Invalid listening port")

        # Update config
        self._config._host = ip
        self._config._port = port

        try:
            # Setup listeners
            listener = upkica.connectors.ZMQListener(
                self._config, self._storage, self._profiles, self._admins
            )
        except Exception as err:
            raise upkica.core.UPKIError(42, f"Unable to initialize listener: {err}")

        try:
            t1 = threading.Thread(
                target=listener.run,
                args=(
                    ip,
                    port,
                ),
                name="uPKI CA listener",
            )
            t1.daemon = True
            t1.start()

            # Stay here to catch Keyboard interrupt
            t1.join()
            while True:
                time.sleep(100)
        except (KeyboardInterrupt, SystemExit):
            self.output("Quitting...", color="red")
            self.output("Bye", color="red")
            raise SystemExit()
