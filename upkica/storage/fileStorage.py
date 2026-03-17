# -*- coding:utf-8 -*-

"""
File-based storage implementation for uPKI.

This module provides a file-based storage backend using TinyDB for storing
certificate information and the filesystem for storing certificates, keys,
and requests.
"""

import os
import time
import shutil
import tinydb
import datetime
from typing import Any

import upkica

from .abstractStorage import AbstractStorage


class FileStorage(AbstractStorage):
    """File-based storage backend for uPKI.

    This class implements the AbstractStorage interface using TinyDB databases
    stored as JSON files and the filesystem for certificates, private keys,
    and certificate requests.

    Attributes:
        _serials_db: Path to serial numbers database.
        _nodes_db: Path to nodes database.
        _admins_db: Path to administrators database.
        _profiles_db: Path to profiles directory.
        _certs_db: Path to certificates directory.
        _reqs_db: Path to certificate requests directory.
        _keys_db: Path to private keys directory.
        db: Dictionary containing TinyDB database handles.
        _options: Storage configuration options.
        _connected: Connection status flag.
        _initialized: Initialization status flag.

    Args:
        logger: UpkiLogger instance for logging.
        options: Dictionary containing storage configuration options.
                 Must include 'path' key specifying the storage directory.

    Raises:
        Exception: If 'path' option is missing or initialization fails.
    """

    def __init__(self, logger: Any, options: dict) -> None:
        """Initialize FileStorage.

        Args:
            logger: UpkiLogger instance for logging.
            options: Dictionary containing 'path' key for storage directory.

        Raises:
            Exception: If 'path' option is missing or initialization fails.
        """
        try:
            super(FileStorage, self).__init__(logger)
        except Exception as err:
            raise Exception(err)

        try:
            options["path"]
        except KeyError:
            raise Exception("Missing mandatory DB options")

        # Define values (pseudo-db)
        self._serials_db = os.path.join(options["path"], ".serials.json")
        self._nodes_db = os.path.join(options["path"], ".nodes.json")
        self._admins_db = os.path.join(options["path"], ".admins.json")
        self._profiles_db = os.path.join(options["path"], "profiles")
        self._certs_db = os.path.join(options["path"], "certs")
        self._reqs_db = os.path.join(options["path"], "reqs")
        self._keys_db = os.path.join(options["path"], "private")

        # Setup handles
        self.db: dict = {"serials": None, "nodes": None}
        self._options = options

        # Setup flags
        self._connected = False
        self._initialized = self._is_initialized()

    def _is_initialized(self) -> bool:
        """Check if storage is initialized.

        Verifies that all required files and directories exist for the
        file-based storage to function properly.

        Returns:
            True if storage is initialized, False otherwise.
        """
        # Check DB file, profiles, public, requests and private exists
        if not os.path.isfile(os.path.join(self._keys_db, "ca.key")):
            return False
        if not os.path.isfile(os.path.join(self._reqs_db, "ca.csr")):
            return False
        if not os.path.isfile(os.path.join(self._certs_db, "ca.crt")):
            return False
        if not os.path.isdir(self._profiles_db):
            return False
        if not os.path.isfile(self._serials_db):
            return False
        if not os.path.isfile(self._nodes_db):
            return False
        if not os.path.isfile(self._admins_db):
            return False

        return True

    def initialize(self) -> bool:
        """Initialize storage backend.

        Creates the directory structure required for file-based storage
        including profiles, certificates, private keys, and requests directories.

        Returns:
            True if initialization successful.

        Raises:
            Exception: If directory creation fails.
        """
        try:
            self.output(
                "Create directory structure on {p}".format(p=self._options["path"]),
                level="DEBUG",
            )
            # Create directories
            for repo in ["profiles/", "certs/", "private/", "reqs/"]:
                self._mkdir_p(os.path.join(self._options["path"], repo))
        except Exception as err:
            raise Exception("Unable to create directories: {e}".format(e=err))

        return True

    def connect(self) -> bool:
        """Connect to storage backend.

        Opens TinyDB database handles for serial numbers, nodes, and
        administrators.

        Returns:
            True if connection successful.

        Raises:
            Exception: If database connection fails.
        """
        try:
            # Create serialFile
            self.db["serials"] = tinydb.TinyDB(self._serials_db)
            # Create indexFile
            self.db["nodes"] = tinydb.TinyDB(self._nodes_db)
            # Create adminFile
            self.db["admins"] = tinydb.TinyDB(self._admins_db)
            self.output(
                "FileDB connected to directory dir://{p}".format(
                    p=self._options["path"]
                ),
                level="DEBUG",
            )
        except Exception as err:
            raise Exception(err)

        # Set flag
        self._connected = True

        return True

    def list_admins(self) -> list:
        """List all administrators.

        Returns:
            List of administrator records from the database.
        """
        admins = self.db["admins"].all()

        return admins

    def add_admin(self, dn: str) -> bool:
        """Add an administrator.

        Args:
            dn: Distinguished Name of the node to promote to admin.

        Returns:
            True if admin added successfully.

        Raises:
            Exception: If node does not exist or CN extraction fails.
        """
        if not self.exists(dn):
            raise Exception("This node does not exists")

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception("Unable to extract CN from admin DN")

        Query = tinydb.Query()

        self.output(
            "Promote user {c} to admin role in nodes DB".format(c=cn), level="DEBUG"
        )
        self.db["nodes"].update({"Admin": True}, Query.DN.search(dn))

        self.output("Add admin {d} in admins DB".format(d=dn), level="DEBUG")
        self.db["admins"].insert({"name": cn, "dn": dn})

        return True

    def delete_admin(self, dn: str) -> bool:
        """Remove an administrator.

        Args:
            dn: Distinguished Name of the admin to remove.

        Returns:
            True if admin removed successfully.

        Raises:
            Exception: If node does not exist or CN extraction fails.
        """
        if not self.exists(dn):
            raise Exception("This node does not exists")

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception("Unable to extract CN from admin DN")

        Query = tinydb.Query()

        self.output(
            "Un-Promote user {c} to admin role in nodes DB".format(c=cn), level="DEBUG"
        )
        self.db["nodes"].update({"Admin": False}, Query.DN.search(dn))

        self.output("Remove admin {d} from admins DB".format(d=dn), level="DEBUG")
        self.db["admins"].remove(tinydb.where("dn") == dn)

        return True

    def list_profiles(self) -> dict:
        """List all available profiles.

        Returns:
            Dictionary mapping profile names to their configuration data.
        """
        profiles = dict({})

        # Parse all profiles set
        for file in os.listdir(self._profiles_db):
            if file.endswith(".yml"):
                # Only store filename without extensions
                filename = os.path.splitext(file)[0]
                try:
                    data = self._parseYAML(os.path.join(self._profiles_db, file))
                    clean = self._check_profile(data)
                    profiles[filename] = dict(clean)
                except Exception as err:
                    self.output(err, level="ERROR")
                    # If file is not a valid profile just skip it
                    continue

        return profiles

    def load_profile(self, name: str) -> dict:
        """Load a specific profile by name.

        Args:
            name: Name of the profile to load.

        Returns:
            Profile configuration data.

        Raises:
            Exception: If profile cannot be loaded.
        """
        try:
            data = self._parseYAML(
                os.path.join(self._profiles_db, "{n}.yml".format(n=name))
            )
        except Exception as err:
            raise Exception(err)

        return data

    def update_profile(self, original: str, name: str, clean: dict) -> bool:
        """Update an existing profile.

        Args:
            original: Original profile name.
            name: New profile name.
            clean: Profile configuration data.

        Returns:
            True if profile updated successfully.

        Raises:
            Exception: If profile update fails.
        """
        try:
            self._storeYAML(
                os.path.join(self._profiles_db, "{n}.yml".format(n=name)), clean
            )
        except Exception as err:
            raise Exception(err)

        return True

    def store_profile(self, name: str, clean: dict) -> bool:
        """Store a new profile.

        Args:
            name: Profile name.
            clean: Profile configuration data.

        Returns:
            True if profile stored successfully.

        Raises:
            Exception: If profile storage fails.
        """
        try:
            self._storeYAML(
                os.path.join(self._profiles_db, "{n}.yml".format(n=name)), clean
            )
        except Exception as err:
            raise Exception(err)

        return True

    def delete_profile(self, name: str) -> bool:
        """Delete a profile.

        Args:
            name: Name of the profile to delete.

        Returns:
            True if profile deleted successfully.

        Raises:
            Exception: If profile deletion fails.
        """
        try:
            os.remove(os.path.join(self._profiles_db, "{n}.yml".format(n=name)))
        except Exception as err:
            raise Exception("Unable to delete profile file: {e}".format(e=err))

        return True

    def serial_exists(self, serial: int) -> bool:
        """Check if serial number exists in storage.

        Args:
            serial: Certificate serial number to check.

        Returns:
            True if serial exists, False otherwise.
        """
        Serial = tinydb.Query()
        return self.db["serials"].contains(Serial.number == serial)

    def store_key(
        self,
        pkey: bytes,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> str:
        """Store private key in storage.

        Creates a PEM or DER encoded file in the private keys directory.

        Args:
            pkey: Private key bytes to store.
            nodename: Name identifier for the key.
            ca: Whether this is a CA key (default: False).
            encoding: Key encoding format - "PEM", "DER", "PFX", or "P12" (default: "PEM").

        Returns:
            Path where key was stored.

        Raises:
            Exception: If nodename is None.
            NotImplementedError: If encoding is not supported.
        """
        if nodename is None:
            raise Exception("Can not store private key with null name.")

        if encoding == "PEM":
            ext = "key"
        elif encoding in "DER":
            ext = "key"
        elif encoding in ["PFX", "P12"]:
            # ext = 'p12'
            raise NotImplementedError("P12 private encoding not yet supported, sorry!")
        else:
            raise NotImplementedError("Unsupported private key encoding")

        key_path = os.path.join(self._keys_db, "{n}.{e}".format(n=nodename, e=ext))
        with open(key_path, "wb") as raw:
            raw.write(pkey)

        try:
            # Protect CA private keys from rewrite
            if ca:
                os.chmod(key_path, 0o400)
        except Exception as err:
            raise Exception(err)

        return key_path

    def store_request(
        self,
        req: bytes,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> str:
        """Store certificate request in storage.

        Creates a PEM or DER encoded file in the requests directory.

        Args:
            req: Certificate request bytes to store.
            nodename: Name identifier for the request.
            ca: Whether this is a CA request (default: False).
            encoding: Request encoding format - "PEM", "DER", "PFX", or "P12" (default: "PEM").

        Returns:
            Path where request was stored.

        Raises:
            Exception: If nodename is None.
            NotImplementedError: If encoding is not supported.
        """
        if nodename is None:
            raise Exception("Can not store certificate request with null name.")

        if encoding == "PEM":
            ext = "csr"
        elif encoding in "DER":
            ext = "csr"
        elif encoding in ["PFX", "P12"]:
            # ext = 'p12'
            raise NotImplementedError(
                "P12 certificate request encoding not yet supported, sorry!"
            )
        else:
            raise NotImplementedError("Unsupported certificate request encoding")

        csr_path = os.path.join(self._reqs_db, "{n}.{e}".format(n=nodename, e=ext))
        with open(csr_path, "wb") as raw:
            raw.write(req)

        try:
            # Protect CA certificate request from rewrite
            if ca:
                os.chmod(csr_path, 0o400)
        except Exception as err:
            raise Exception(err)

        return csr_path

    def download_request(self, nodename: str, encoding: str = "PEM") -> str:
        """Download certificate request from storage.

        Args:
            nodename: Name identifier for the request.
            encoding: Request encoding format (default: "PEM").

        Returns:
            Certificate request data as string.

        Raises:
            Exception: If nodename is None or request doesn't exist.
            NotImplementedError: If encoding is not supported.
        """
        if nodename is None:
            raise Exception("Can not download a certificate request with null name")

        if encoding == "PEM":
            ext = "csr"
        elif encoding in "DER":
            ext = "csr"
        elif encoding in ["PFX", "P12"]:
            # ext = 'p12'
            raise NotImplementedError(
                "P12 certificate request encoding not yet supported, sorry!"
            )
        else:
            raise NotImplementedError("Unsupported certificate request encoding")

        csr_path = os.path.join(self._reqs_db, "{n}.{e}".format(n=nodename, e=ext))

        if not os.path.isfile(csr_path):
            raise Exception("Certificate request does not exists!")

        with open(csr_path, "rt") as node_file:
            result = node_file.read()

        return result

    def delete_request(
        self,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> bool:
        """Delete certificate request from storage.

        Args:
            nodename: Name identifier for the request.
            ca: Whether this is a CA request (default: False).
            encoding: Request encoding format (default: "PEM").

        Returns:
            True if deletion successful.

        Raises:
            Exception: If nodename is None or deletion fails.
            NotImplementedError: If encoding is not supported.
        """
        if nodename is None:
            raise Exception("Can not delete certificate request with null name.")

        if encoding == "PEM":
            ext = "csr"
        elif encoding in "DER":
            ext = "csr"
        elif encoding in ["PFX", "P12"]:
            # ext = 'p12'
            raise NotImplementedError(
                "P12 certificate request encoding not yet supported, sorry!"
            )
        else:
            raise NotImplementedError("Unsupported certificate request encoding")

        csr_path = os.path.join(self._reqs_db, "{n}.{e}".format(n=nodename, e=ext))
        # If CSR does NOT exists: no big deal
        if os.path.isfile(csr_path):
            try:
                if ca:
                    # Remove old certificate protection
                    os.chmod(csr_path, 0o600)
                # Then delete file
                os.remove(csr_path)
            except Exception as err:
                raise Exception(
                    "Unable to delete certificate request: {e}".format(e=err)
                )

        return True

    def store_public(
        self,
        crt: bytes,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> str:
        """Store public certificate in storage.

        Creates a PEM, DER, or PFX encoded file in the certificates directory.

        Args:
            crt: Certificate bytes to store.
            nodename: Name identifier for the certificate.
            ca: Whether this is a CA certificate (default: False).
            encoding: Certificate encoding format - "PEM", "DER", "PFX", or "P12" (default: "PEM").

        Returns:
            Path where certificate was stored.

        Raises:
            Exception: If nodename is None.
            NotImplementedError: If encoding is not supported.
        """
        if nodename is None:
            raise Exception("Can not store certificate with null name.")

        if encoding == "PEM":
            ext = "crt"
        elif encoding in "DER":
            ext = "cer"
        elif encoding in ["PFX", "P12"]:
            # ext = 'p12'
            raise NotImplementedError(
                "P12 certificate encoding not yet supported, sorry!"
            )
        else:
            raise NotImplementedError("Unsupported certificate encoding")

        crt_path = os.path.join(self._certs_db, "{n}.{e}".format(n=nodename, e=ext))
        with open(crt_path, "wb") as raw:
            raw.write(crt)

        try:
            # Protect CA certificate from rewrite
            if ca:
                os.chmod(crt_path, 0o400)
        except Exception as err:
            raise Exception(err)

        return crt_path

    def download_public(self, nodename: str, encoding: str = "PEM") -> str:
        """Download public certificate from storage.

        Args:
            nodename: Name identifier for the certificate.
            encoding: Certificate encoding format (default: "PEM").

        Returns:
            Certificate data as string.

        Raises:
            Exception: If nodename is None or certificate doesn't exist.
            NotImplementedError: If encoding is not supported.
        """
        if nodename is None:
            raise Exception("Can not download a public certificate with name null")

        if encoding == "PEM":
            ext = "crt"
        elif encoding in "DER":
            ext = "cer"
        elif encoding in ["PFX", "P12"]:
            # ext = 'p12'
            raise NotImplementedError(
                "P12 certificate encoding not yet supported, sorry!"
            )
        else:
            raise NotImplementedError("Unsupported certificate encoding")

        filename = "{n}.{e}".format(n=nodename, e=ext)
        node_path = os.path.join(self._certs_db, filename)

        if not os.path.isfile(node_path):
            raise Exception("Certificate does not exists!")

        with open(node_path, "rt") as node_file:
            result = node_file.read()

        return result

    def delete_public(
        self,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> bool:
        """Delete public certificate from storage.

        Args:
            nodename: Name identifier for the certificate.
            ca: Whether this is a CA certificate (default: False).
            encoding: Certificate encoding format (default: "PEM").

        Returns:
            True if deletion successful.

        Raises:
            Exception: If nodename is None or deletion fails.
            NotImplementedError: If encoding is not supported.
        """
        if nodename is None:
            raise Exception("Can not delete certificate with null name.")

        if encoding == "PEM":
            ext = "crt"
        elif encoding in "DER":
            ext = "cer"
        elif encoding in ["PFX", "P12"]:
            # ext = 'p12'
            raise NotImplementedError(
                "P12 certificate encoding not yet supported, sorry!"
            )
        else:
            raise NotImplementedError("Unsupported certificate encoding")

        crt_path = os.path.join(self._certs_db, "{n}.{e}".format(n=nodename, e=ext))
        try:
            if ca:
                # Remove old certificate protection
                os.chmod(crt_path, 0o600)
            # Then delete file
            os.remove(crt_path)
        except Exception as err:
            raise Exception("Unable to delete certificate: {e}".format(e=err))

        return True

    def store_crl(self, crl_pem: bytes) -> bool:
        """Store CRL (PEM encoded) file on disk.

        Args:
            crl_pem: CRL bytes in PEM format.

        Returns:
            True if storage successful.
        """
        crl_path = os.path.join(self._options["path"], "crl.pem")

        # Complete rewrite of file
        # TODO: Also publish updates ?
        with open(crl_path, "wb") as crlfile:
            crlfile.write(crl_pem)

        return True

    def exists(
        self,
        name: str,
        profile: str | None = None,
        uid: int | None = None,
    ) -> bool:
        """Check if node exists in storage.

        Args:
            name: DN (if profile is None) or CN (if profile is set).
            profile: Optional profile name.
            uid: Optional document ID.

        Returns:
            True if node exists, False otherwise.
        """
        Node = tinydb.Query()
        if uid is not None:
            # If uid is set, return corresponding
            return self.db["nodes"].contains(doc_ids=[uid])
        elif profile is None:
            # If profile is empty, must find a DN for name
            return self.db["nodes"].contains(Node.DN == name)
        # Search for name/profile couple entry
        return self.db["nodes"].contains((Node.CN == name) & (Node.Profile == profile))

    def is_valid(self, serial_number: int) -> tuple:
        """Check if certificate serial number is valid.

        Args:
            serial_number: Certificate serial number to check.

        Returns:
            Tuple of (cert_status, revocation_time, revocation_reason).

        Raises:
            Exception: If serial number is missing or certificate not found.
        """
        if serial_number is None:
            raise Exception("Serial number missing")

        self.output("OCSP request against {n} serial".format(n=serial_number))

        Node = tinydb.Query()
        if not self.db["nodes"].contains(Node.Serial == serial_number):
            raise Exception("Certificate does not exists")

        result = self.db["nodes"].search(Node.Serial == serial_number)
        revocation_time = None
        revocation_reason = None

        try:
            cert_status = result[0]["State"]
        except (IndexError, KeyError):
            raise Exception("Certificate not properly configured")

        try:
            revocation_time = result[0]["Revoke_Date"]
            revocation_reason = result[0]["Reason"]
        except (IndexError, KeyError):
            pass

        return (cert_status, revocation_time, revocation_reason)

    def get_ca(self) -> str:
        """Get CA certificate content.

        Returns:
            CA certificate content in PEM format.

        Raises:
            Exception: If CA certificate file cannot be read.
        """
        with open(os.path.join(self._certs_db, "ca.crt"), "rt") as cafile:
            data = cafile.read()

        return data

    def get_ca_key(self) -> str:
        """Get CA private key content.

        Returns:
            CA private key content in PEM format.

        Raises:
            Exception: If CA key file cannot be read.
        """
        with open(os.path.join(self._keys_db, "ca.key"), "rt") as cafile:
            data = cafile.read()

        return data

    def get_crl(self) -> str:
        """Get CRL content.

        Returns:
            CRL content in PEM format.

        Raises:
            Exception: If CRL file doesn't exist or cannot be read.
        """
        crl_path = os.path.join(self._options["path"], "crl.pem")

        if not os.path.isfile(crl_path):
            raise Exception("CRL as not been generated yet!")

        with open(crl_path, "rt") as crlfile:
            data = crlfile.read()

        return data

    def store_crl(self, crl_pem: bytes) -> bool:
        """Store CRL (PEM encoded) file on disk.

        Args:
            crl_pem: CRL bytes in PEM format.

        Returns:
            True if storage successful.
        """
        crl_path = os.path.join(self._options["path"], "crl.pem")

        # Complete rewrite of file
        # TODO: Also publish updates ?
        with open(crl_path, "wb") as crlfile:
            crlfile.write(crl_pem)

        return True

    def register_node(
        self,
        dn: str,
        profile_name: str,
        profile_data: dict,
        sans: list | None = None,
        keyType: str | None = None,
        keyLen: int | None = None,
        digest: str | None = None,
        duration: int | None = None,
        local: bool = False,
    ) -> int:
        """Register node in DB only.

        Note: no checks are done on values.

        Args:
            dn: Distinguished Name.
            profile_name: Profile name to use.
            profile_data: Profile configuration data.
            sans: Optional list of Subject Alternative Names.
            keyType: Optional key type override.
            keyLen: Optional key length override.
            digest: Optional digest algorithm override.
            duration: Optional validity duration override.
            local: Whether this is a local node (default: False).

        Returns:
            Document ID of the inserted node.

        Raises:
            Exception: If CN extraction fails.
        """
        if sans is None:
            sans = []

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception("Unable to extract CN")

        # Auto-configure infos based on profile if necessary
        if keyType is None:
            keyType = profile_data["keyType"]
        if keyLen is None:
            keyLen = profile_data["keyLen"]
        if digest is None:
            digest = profile_data["digest"]
        if duration is None:
            duration = profile_data["duration"]

        try:
            altnames = profile_data["altnames"]
        except KeyError:
            altnames = False
        try:
            domain = profile_data["domain"]
        except KeyError:
            domain = None

        Node = tinydb.Query()
        now = time.time()
        created_human = datetime.datetime.utcfromtimestamp(now).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        return self.db["nodes"].insert(
            {
                "Admin": False,
                "DN": dn,
                "CN": cn,
                "Sans": sans,
                "State": "Init",
                "Created": int(now),
                "Created_human": created_human,
                "Start": None,
                "Start_human": None,
                "Expire": None,
                "Expire_human": None,
                "Duration": duration,
                "Serial": None,
                "Profile": profile_name,
                "Domain": domain,
                "Altnames": altnames,
                "Remote": True,
                "Local": local,
                "KeyType": keyType,
                "KeyLen": keyLen,
                "Digest": digest,
            }
        )

    def update_node(
        self,
        dn: str,
        profile_name: str,
        profile_data: dict,
        sans: list | None = None,
        keyType: str | None = None,
        keyLen: int | None = None,
        digest: str | None = None,
        duration: int | None = None,
        local: bool = False,
    ) -> bool:
        """Update node in DB only.

        Note: no checks are done on values.

        Args:
            dn: Distinguished Name.
            profile_name: Profile name to use.
            profile_data: Profile configuration data.
            sans: Optional list of Subject Alternative Names.
            keyType: Optional key type override.
            keyLen: Optional key length override.
            digest: Optional digest algorithm override.
            duration: Optional validity duration override.
            local: Whether this is a local node (default: False).

        Returns:
            True if update successful.

        Raises:
            Exception: If CN extraction fails.
        """
        if sans is None:
            sans = []

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception("Unable to extract CN")

        # Auto-configure infos based on profile if necessary
        if keyType is None:
            keyType = profile_data["keyType"]
        if keyLen is None:
            keyLen = profile_data["keyLen"]
        if digest is None:
            digest = profile_data["digest"]
        if duration is None:
            duration = profile_data["duration"]

        try:
            altnames = profile_data["altnames"]
        except KeyError:
            altnames = False
        try:
            domain = profile_data["domain"]
        except KeyError:
            domain = None

        # Update can only work on certain fields
        Node = tinydb.Query()
        self.db["nodes"].update({"Profile": profile_name}, Node.DN.search(dn))
        self.db["nodes"].update({"Sans": sans}, Node.DN.search(dn))
        self.db["nodes"].update({"KeyType": keyType}, Node.DN.search(dn))
        self.db["nodes"].update({"KeyLen": keyLen}, Node.DN.search(dn))
        self.db["nodes"].update({"Digest": digest}, Node.DN.search(dn))
        self.db["nodes"].update({"Duration": duration}, Node.DN.search(dn))
        self.db["nodes"].update({"Local": local}, Node.DN.search(dn))

        return True

    def get_node(
        self,
        name: str,
        profile: str | None = None,
        uid: int | None = None,
    ) -> dict:
        """Get a specific node.

        Returns node data and automatically updates expired certificates.

        Args:
            name: DN or CN of the node.
            profile: Optional profile name filter.
            uid: Optional document ID.

        Returns:
            Dictionary with node data.

        Raises:
            Exception: If multiple entries found, unknown entry, or no entry found.
        """
        Node = tinydb.Query()
        if uid is not None:
            # If uid is set, return corresponding
            result = [self.db["nodes"].get(doc_id=uid)]
        elif profile is None:
            # If profile is empty, must find a DN for name
            result = self.db["nodes"].search(Node.DN == name)
        else:
            # Search for name/profile couple entry
            result = self.db["nodes"].search(
                (Node.CN == name) & (Node.Profile == profile)
            )

        if len(result) > 1:
            raise Exception("Multiple entry found...")

        if len(result) == 0:
            raise Exception("Unknown entry")

        try:
            node = dict(result[0])
            node["DN"]
            node["State"]
            node["Expire"]
        except (IndexError, KeyError):
            raise Exception("No entry found")

        if (node["Expire"] != None) and (node["Expire"] <= int(time.time())):
            node["State"] = "Expired"
            self.expire_node(node["DN"])

        return node

    def list_nodes(self) -> list:
        """List all nodes.

        Returns list of all nodes and automatically updates expired ones.

        Returns:
            List of node dictionaries.
        """
        nodes = self.db["nodes"].all()

        # Use loop to clean datas
        for i, node in enumerate(nodes):
            try:
                node["DN"]
                node["Serial"]
                node["State"]
                node["Expire"]
            except KeyError:
                continue
            # Check expiration
            if (node["Expire"] != None) and (node["Expire"] <= int(time.time())):
                nodes[i]["State"] = "Expired"
                try:
                    self.expire_node(node["DN"])
                except Exception:
                    continue

        return nodes

    def get_revoked(self) -> list:
        """Get list of revoked certificates.

        Returns:
            List of revoked certificate node dictionaries.
        """
        Node = tinydb.Query()
        return self.db["nodes"].search(Node.State == "Revoked")

    def activate_node(self, dn: str) -> bool:
        """Activate a pending node.

        Args:
            dn: Distinguished Name of node to activate.

        Returns:
            True if activation successful.
        """
        Node = tinydb.Query()
        # Should set state to Manual if config requires it
        self.db["nodes"].update({"State": "Active"}, Node.DN.search(dn))
        self.db["nodes"].update({"Generated": True}, Node.DN.search(dn))

        return True

    def certify_node(self, dn: str, cert: Any, internal: bool = False) -> bool:
        """Certify a node with a certificate.

        Args:
            dn: Distinguished Name of the node.
            cert: Certificate object to use for certification.
            internal: Whether this is an internal certification (default: False).

        Returns:
            True if certification successful.
        """
        Node = tinydb.Query()

        self.output(
            "Add serial {s} in serial DB".format(s=cert.serial_number), level="DEBUG"
        )
        self.db["serials"].insert({"number": cert.serial_number})

        # Do not register internal certificates (CA/Server/RA)
        if not internal:
            self.output(
                "Add certificate for {d} in node DB".format(d=dn), level="DEBUG"
            )
            self.db["nodes"].update({"Serial": cert.serial_number}, Node.DN.search(dn))
            self.db["nodes"].update({"State": "Valid"}, Node.DN.search(dn))
            # Update start time
            start_time = cert.not_valid_before.timestamp()
            start_human = cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
            self.db["nodes"].update({"Start": int(start_time)}, Node.DN.search(dn))
            self.db["nodes"].update({"Start_human": start_human}, Node.DN.search(dn))
            # Set end time
            end_time = cert.not_valid_after.timestamp()
            end_human = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
            self.db["nodes"].update({"Expire": int(end_time)}, Node.DN.search(dn))
            self.db["nodes"].update({"Expire_human": end_human}, Node.DN.search(dn))
        elif self.exists(dn):
            self.output(
                "Avoid register {d}. Used for internal purpose".format(d=dn),
                level="WARNING",
            )
            self.db["nodes"].remove(tinydb.where("DN") == dn)

        return True

    def expire_node(self, dn: str) -> bool:
        """Mark a node as expired.

        Args:
            dn: Distinguished Name of node to expire.

        Returns:
            True if expiration successful.
        """
        Node = tinydb.Query()
        self.output("Set certificate {d} as expired".format(d=dn), level="DEBUG")

        self.db["nodes"].update({"State": "Expired"}, Node.DN.search(dn))

        return True

    def renew_node(self, serial: int, dn: str, cert: object) -> bool:
        """Renew a node's certificate.

        Args:
            serial: Old certificate serial number.
            dn: Distinguished Name of node to renew.
            cert: New certificate object.

        Returns:
            True if renewal successful.
        """
        Node = tinydb.Query()

        self.output(
            "Remove old serial {s} in serial DB".format(s=serial), level="DEBUG"
        )
        self.db["serials"].remove(tinydb.where("number") == serial)

        self.output(
            "Add new serial {s} in serial DB".format(s=cert.serial_number),
            level="DEBUG",
        )
        self.db["serials"].insert({"number": cert.serial_number})

        # Update start time
        start_time = cert.not_valid_before.timestamp()
        start_human = cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
        self.db["nodes"].update({"Start": int(start_time)}, Node.DN.search(dn))
        self.db["nodes"].update({"Start_human": start_human}, Node.DN.search(dn))

        # Set end time
        end_time = cert.not_valid_after.timestamp()
        end_human = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
        self.db["nodes"].update({"Expire": int(end_time)}, Node.DN.search(dn))
        self.db["nodes"].update({"Expire_human": end_human}, Node.DN.search(dn))

        return True

    def revoke_node(self, dn: str, reason: str = "unspecified") -> bool:
        """Revoke a node's certificate.

        Args:
            dn: Distinguished Name of node to revoke.
            reason: Revocation reason (default: "unspecified").

        Returns:
            True if revocation successful.
        """
        Node = tinydb.Query()
        # self.db['nodes'].update({"Start":None},Node.DN.search(dn))
        # self.db['nodes'].update({"Expire":None},Node.DN.search(dn))
        self.db["nodes"].update({"State": "Revoked"}, Node.DN.search(dn))
        self.db["nodes"].update({"Reason": reason}, Node.DN.search(dn))
        self.db["nodes"].update(
            {"Revoke_Date": datetime.datetime.utcnow().strftime("%Y%m%d%H%M%SZ")},
            Node.DN.search(dn),
        )

        return True

    def unrevoke_node(self, dn: str) -> bool:
        """Unrevoke a node's certificate.

        Args:
            dn: Distinguished Name of node to unrevoke.

        Returns:
            True if unrevocation successful.
        """
        Node = tinydb.Query()
        # self.db['nodes'].update({"Start":None},Node.DN.search(dn))
        # self.db['nodes'].update({"Expire":None},Node.DN.search(dn))
        self.db["nodes"].update({"State": "Valid"}, Node.DN.search(dn))
        self.db["nodes"].update({"Reason": None}, Node.DN.search(dn))
        self.db["nodes"].update({"Revoke_Date": None}, Node.DN.search(dn))

        return True

    def delete_node(self, dn: str, serial: int) -> bool:
        """Delete a node from storage.

        Args:
            dn: Distinguished Name of node to delete.
            serial: Certificate serial number.

        Returns:
            True if deletion successful.
        """
        self.db["serials"].remove(tinydb.where("number") == serial)
        self.db["nodes"].remove(tinydb.where("DN") == dn)

        return True
