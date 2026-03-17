# -*- coding:utf-8 -*-

"""
ZMQ Register connector for uPKI RA server.

This module provides the ZMQRegister class which handles registration
of new nodes via ZeroMQ communication.
"""

import os
import sys
import hashlib
import datetime
import time
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import upkica

from .listener import Listener


class ZMQRegister(Listener):
    """ZMQ-based Registration Authority listener.

    This class extends the base Listener class to handle node registration
    via ZeroMQ communication. It registers RA servers, clients, and admins.

    Attributes:
        _public: PublicCert handler.

    Args:
        config: Configuration object.
        storage: Storage backend instance.
        profiles: Profiles manager instance.
        admins: Admins manager instance.

    Raises:
        Exception: If initialization fails.
    """

    def __init__(self, config: Any, storage: Any, profiles: Any, admins: Any) -> None:
        """Initialize ZMQRegister.

        Args:
            config: Configuration object.
            storage: Storage backend instance.
            profiles: Profiles manager instance.
            admins: Admins manager instance.

        Raises:
            Exception: If initialization fails.
        """
        try:
            super(ZMQRegister, self).__init__(config, storage, profiles, admins)
        except Exception as err:
            raise Exception(err)

        # Register handles to X509
        self._public = upkica.ca.PublicCert(config)

    def __generate_node(
        self, profile_name: str, name: str, sans: list | None = None
    ) -> str:
        """Generate a node with simple profile name and CN.

        Args:
            profile_name: Profile name to use.
            name: Common Name for the node.
            sans: Optional list of Subject Alternative Names.

        Returns:
            Distinguished Name of the registered node.

        Raises:
            upkica.core.UPKIError: If profile loading or registration fails.
        """
        if sans is None:
            sans = []

        try:
            # Load RA specific profile
            profile = self._profiles.load(profile_name)
        except Exception as err:
            raise upkica.core.UPKIError(103, err)

        # Generate DN based on profile
        ent = list()
        for e in profile["subject"]:
            for k, v in e.items():
                ent.append("{k}={v}".format(k=k, v=v))
        base_dn = "/".join(ent)
        # Setup node name
        dn = "/{b}/CN={n}".format(b=base_dn, n=name)

        if self._storage.exists(dn):
            raise Exception("RA server already registered")

        try:
            # Register node
            self._storage.register_node(dn, profile_name, profile, sans=sans)
        except Exception as err:
            raise upkica.core.UPKIError(
                104, "Unable to register RA node: {e}".format(e=err)
            )

        return dn

    def _upki_list_profiles(self, params: dict) -> dict:
        """List all profiles.

        Args:
            params: Request parameters (unused).

        Returns:
            Dictionary of available profiles.
        """
        # Avoid profile protection
        return self._profiles._profiles_list

    def _upki_register(self, params: dict) -> dict:
        """Register a new RA server.

        Args:
            params: Dictionary containing 'seed' for registration.

        Returns:
            Dictionary with registered node DNs.

        Raises:
            upkica.core.UPKIError: If seed is missing, invalid, or registration fails.
            Exception: If domain is not defined or certificates cannot be generated.
        """
        try:
            seed = params["seed"]
        except KeyError:
            raise upkica.core.UPKIError(100, "Missing seed.")

        try:
            # Register seed value
            tmp = "seed:{s}".format(s=seed)
            cookie = hashlib.sha1(tmp.encode("utf-8")).hexdigest()
        except Exception as err:
            raise upkica.core.UPKIError(
                101, "Unable to generate seed: {e}".format(e=err)
            )

        if cookie != self._config._seed:
            raise upkica.core.UPKIError(102, "Invalid seed.")

        try:
            domain = self._profiles._profiles_list["server"]["domain"]
        except KeyError:
            raise Exception("Domain not defined in server profile")

        try:
            # Register TLS client for usage with CA
            ra_node = self.__generate_node("user", seed)
        except Exception as err:
            raise Exception("Unable to generate TLS client: {e}".format(e=err))

        try:
            # Register Server for SSL website
            server_node = self.__generate_node(
                "server",
                "certificates.{d}".format(d=domain),
                sans=["certificates.{d}".format(d=domain)],
            )
        except Exception as err:
            raise Exception("Unable to generate server certificate: {e}".format(e=err))

        try:
            # Register admin for immediate usage
            admin_node = self.__generate_node("admin", "admin")
        except Exception as err:
            raise Exception("Unable to generate admin certificate: {e}".format(e=err))

        try:
            self._storage.add_admin(admin_node)
        except Exception as err:
            raise Exception("Unable to register admin: {e}".format(e=err))

        return {"ra": ra_node, "certificates": server_node, "admin": admin_node}

    def _upki_get_node(self, params: dict) -> dict:
        """Get a specific node.

        Args:
            params: Dictionary with 'cn' and optional 'profile', or a string DN.

        Returns:
            Node dictionary.

        Raises:
            Exception: If node retrieval fails.
        """
        try:
            if isinstance(params, dict):
                node = self._storage.get_node(params["cn"], profile=params["profile"])
            elif isinstance(params, str):
                node = self._storage.get_node(params)
            else:
                raise NotImplementedError("Unsupported params")
        except Exception as err:
            raise Exception(err)

        if (node["Expire"] != None) and (node["Expire"] <= int(time.time())):
            node["State"] = "Expired"
            self._storage.expire_node(node["DN"])

        return node

    def _upki_done(self, seed: str) -> bool:
        """Close the connection.

        Args:
            seed: Seed value for validation.

        Returns:
            True if connection closed successfully.

        Raises:
            upkica.core.UPKIError: If seed processing fails.
        """
        try:
            # Register seed value
            tmp = "seed:{s}".format(s=seed)
            cookie = hashlib.sha1(tmp.encode("utf-8")).hexdigest()
        except Exception as err:
            raise upkica.core.UPKIError(
                101, "Unable to generate seed: {e}".format(e=err)
            )

        if cookie == self._config._seed:
            # Closing connection
            self._run = False

        return True

    def _upki_sign(self, params: dict) -> dict:
        """Sign a certificate request.

        Args:
            params: Dictionary containing 'csr' PEM-encoded certificate request.

        Returns:
            Dictionary with signed certificate.

        Raises:
            upkica.core.UPKIError: If CSR is missing.
            Exception: If signing fails or certificate is invalid.
        """
        try:
            csr = x509.load_pem_x509_csr(
                params["csr"].encode("utf-8"), default_backend()
            )
        except KeyError:
            raise upkica.core.UPKIError(105, "Missing CSR data")

        try:
            dn = self._get_dn(csr.subject)
        except Exception as err:
            raise Exception("Unable to get DN: {e}".format(e=err))

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception("Unable to get CN: {e}".format(e=err))

        try:
            node = self._storage.get_node(dn)
        except Exception as err:
            raise Exception("Unable to retrieve node: {e}".format(e=err))

        if node["State"] in ["Valid", "Revoked", "Expired"]:
            if node["State"] == "Valid":
                raise Exception("Certificate already generated!")
            elif node["State"] == "Revoked":
                raise Exception("Certificate is revoked!")
            elif node["State"] == "Expired":
                raise Exception("Certificate has expired!")

        try:
            profile = self._profiles.load(node["Profile"])
        except Exception as err:
            raise Exception("Unable to load profile in generate: {e}".format(e=err))

        try:
            pub_cert = self._public.generate(
                csr,
                self._ca["cert"],
                self._ca["key"],
                profile,
                duration=node["Duration"],
                sans=node["Sans"],
            )
        except Exception as err:
            raise Exception("Unable to generate Public Key: {e}".format(e=err))

        try:
            self.output(
                "Certify node {n} with profile {p}".format(n=dn, p=node["Profile"])
            )
            self._storage.certify_node(dn, pub_cert, internal=True)
        except Exception as err:
            raise Exception(err)

        return {"certificate": self._public.dump(pub_cert).decode("utf-8")}
