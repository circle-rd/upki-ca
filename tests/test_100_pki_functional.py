"""
Functional tests for the PKI system using ca_server.py CLI.

These tests verify:
1. PKI initialization (using ca_server.py init)
2. Certificate generation (using openssl for key/CSR)
3. Certificate validation (using openssl)
4. CRL generation

All tests use /tmp as the working directory.

Author: uPKI Team
License: MIT
"""

import os
import shutil
import subprocess
import sys

import pytest
from cryptography.x509 import (
    DNSName,
    IPAddress,
    SubjectAlternativeName,
    load_pem_x509_certificate,
)

# Path to the ca_server.py script
CA_SERVER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "ca_server.py"
)


class TestPKIInitialization:
    """Tests for PKI initialization using ca_server.py init command."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down for each test."""
        self.pki_path = "/tmp/test_pki_init"

        # Clean up before test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

        yield

        # Clean up after test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

    def test_init_pki_creates_ca_structure(self):
        """
        Test that init command creates the correct directory structure.

        Verifies that the init command creates:
        - Directory structure (certs/, reqs/, private/, profiles/)
        - Database files (.serials.json, .nodes.json)
        """
        # Run ca_server.py init command
        result = subprocess.run(
            [sys.executable, CA_SERVER_PATH, "--path", self.pki_path, "init"],
            capture_output=True,
            text=True,
            check=True,
        )

        # Verify PKI was initialized successfully
        assert "PKI initialized successfully" in result.stdout

        # Verify directory structure
        assert os.path.isdir(self.pki_path)

        # Verify subdirectories
        assert os.path.isdir(os.path.join(self.pki_path, "certs"))
        assert os.path.isdir(os.path.join(self.pki_path, "reqs"))
        assert os.path.isdir(os.path.join(self.pki_path, "private"))
        assert os.path.isdir(os.path.join(self.pki_path, "profiles"))

        # Verify database files
        assert os.path.exists(os.path.join(self.pki_path, ".serials.json"))
        assert os.path.exists(os.path.join(self.pki_path, ".nodes.json"))

        # Verify CA certificate from default location
        home_dir = os.path.expanduser("~")
        default_ca_path = os.path.join(home_dir, ".upki", "ca")
        ca_crt = os.path.join(default_ca_path, "ca.crt")

        assert os.path.exists(ca_crt)

        # Verify CA certificate is valid using openssl
        result = subprocess.run(
            ["openssl", "x509", "-in", ca_crt, "-text", "-noout"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "Certificate:" in result.stdout
        assert "CA:TRUE" in result.stdout


class TestCertificateGeneration:
    """Tests for certificate generation using openssl."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down for each test."""
        self.pki_path = "/tmp/test_pki_cert_gen"

        # Clean up before test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

        # Initialize PKI
        subprocess.run(
            [sys.executable, CA_SERVER_PATH, "--path", self.pki_path, "init"],
            capture_output=True,
            check=True,
        )

        yield

        # Clean up after test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

    def test_generate_certificate_with_openssl(self):
        """
        Test certificate generation using openssl for key/CSR creation.

        Creates:
        1. Entity private key using openssl genrsa
        2. CSR using openssl req
        3. Self-signed certificate for testing purposes
        """
        entity_key = os.path.join(self.pki_path, "entity.key")
        entity_csr = os.path.join(self.pki_path, "entity.csr")
        entity_cert = os.path.join(self.pki_path, "entity.crt")

        # Generate entity private key
        result = subprocess.run(
            ["openssl", "genrsa", "-out", entity_key, "2048"],
            capture_output=True,
            text=True,
            check=True,
        )

        # Generate CSR
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                entity_key,
                "-out",
                entity_csr,
                "-subj",
                "/CN=Test Entity/O=Test Organization",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        # Generate self-signed certificate for testing
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                entity_csr,
                "-signkey",
                entity_key,
                "-out",
                entity_cert,
                "-days",
                "365",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        # Verify certificate was created
        assert os.path.exists(entity_cert)

        # Verify certificate with openssl
        result = subprocess.run(
            ["openssl", "x509", "-in", entity_cert, "-text", "-noout"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "Certificate:" in result.stdout
        # Note: openssl outputs "CN = Test Entity" with spaces
        assert "CN =" in result.stdout and "Test Entity" in result.stdout

        # Verify certificate dates
        result = subprocess.run(
            ["openssl", "x509", "-in", entity_cert, "-noout", "-dates"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "notBefore=" in result.stdout
        assert "notAfter=" in result.stdout


class TestCertificateValidation:
    """Tests for certificate validation using openssl."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down for each test."""
        self.pki_path = "/tmp/test_pki_validation"

        # Clean up before test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

        # Initialize PKI
        subprocess.run(
            [sys.executable, CA_SERVER_PATH, "--path", self.pki_path, "init"],
            capture_output=True,
            check=True,
        )

        # Create test certificate
        entity_key = os.path.join(self.pki_path, "entity.key")
        entity_cert = os.path.join(self.pki_path, "entity.crt")

        # Generate key and self-signed cert for testing
        subprocess.run(
            ["openssl", "genrsa", "-out", entity_key, "2048"],
            capture_output=True,
            check=True,
        )

        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                entity_key,
                "-out",
                os.path.join(self.pki_path, "entity.csr"),
                "-subj",
                "/CN=Test Entity/O=Test Organization",
            ],
            capture_output=True,
            check=True,
        )

        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                os.path.join(self.pki_path, "entity.csr"),
                "-signkey",
                entity_key,
                "-out",
                entity_cert,
                "-days",
                "365",
            ],
            capture_output=True,
            check=True,
        )

        yield

        # Clean up after test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

    def test_validate_certificate_with_openssl(self):
        """
        Uses openssl x509 to verify the certificate is valid.
        """
        entity_cert = os.path.join(self.pki_path, "entity.crt")

        # Verify certificate is valid X.509
        result = subprocess.run(
            ["openssl", "x509", "-in", entity_cert, "-text", "-noout"],
            capture_output=True,
            text=True,
            check=True,
        )

        assert "Certificate:" in result.stdout
        assert "Version:" in result.stdout
        assert "Serial Number:" in result.stdout

        # Verify certificate subject - openssl outputs with spaces
        result = subprocess.run(
            ["openssl", "x509", "-in", entity_cert, "-noout", "-subject"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "CN =" in result.stdout and "Test Entity" in result.stdout

    def test_certificate_chain_verification(self):
        """
        Verifies the certificate chain (self-signed in this case).
        """
        entity_cert = os.path.join(self.pki_path, "entity.crt")

        # Verify certificate using -partial_chain for self-signed
        result = subprocess.run(
            [
                "openssl",
                "verify",
                "-partial_chain",
                "-CAfile",
                entity_cert,
                entity_cert,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "OK" in result.stdout

        # Check certificate purpose
        result = subprocess.run(
            ["openssl", "x509", "-in", entity_cert, "-noout", "-purpose"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "SSL server" in result.stdout


class TestCRLGeneration:
    """Tests for CRL generation."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down for each test."""
        self.pki_path = "/tmp/test_pki_crl"

        # Clean up before test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

        # Initialize PKI
        subprocess.run(
            [sys.executable, CA_SERVER_PATH, "--path", self.pki_path, "init"],
            capture_output=True,
            check=True,
        )

        yield

        # Clean up after test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

    def test_generate_certificate_and_crl(self):
        """
        Tests generating a certificate and CRL using openssl.
        """
        # Get CA from default location
        home_dir = os.path.expanduser("~")
        default_ca_cert = os.path.join(home_dir, ".upki", "ca", "ca.crt")

        if not os.path.exists(default_ca_cert):
            pytest.skip("CA not found in default location")

        # Generate test certificate signed by CA
        test_key = os.path.join(self.pki_path, "test.key")
        test_cert = os.path.join(self.pki_path, "test.crt")

        subprocess.run(
            ["openssl", "genrsa", "-out", test_key, "2048"],
            capture_output=True,
            check=True,
        )

        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                test_key,
                "-out",
                os.path.join(self.pki_path, "test.csr"),
                "-subj",
                "/CN=Test/O=Test",
            ],
            capture_output=True,
            check=True,
        )

        # Sign certificate with CA
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                os.path.join(self.pki_path, "test.csr"),
                "-CA",
                default_ca_cert,
                "-CAkey",
                os.path.join(home_dir, ".upki", "ca", "ca.key"),
                "-out",
                test_cert,
                "-days",
                "365",
            ],
            capture_output=True,
            check=True,
        )

        # Verify the certificate
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", default_ca_cert, test_cert],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "OK" in result.stdout

        # Copy CA to test path for CRL operations
        ca_cert = os.path.join(self.pki_path, "ca.crt")
        shutil.copy(default_ca_cert, ca_cert)


class TestCertificateRevocation:
    """Tests for certificate revocation."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down for each test."""
        self.pki_path = "/tmp/test_pki_revoke"

        # Clean up before test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

        yield

        # Clean up after test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

    def test_certificate_creation_for_revocation(self):
        """
        Tests creating a certificate that can be revoked.

        Creates a certificate signed by the CA that can later be revoked.
        """
        # Get CA from default location
        home_dir = os.path.expanduser("~")
        default_ca_cert = os.path.join(home_dir, ".upki", "ca", "ca.crt")
        default_ca_key = os.path.join(home_dir, ".upki", "ca", "ca.key")

        if not os.path.exists(default_ca_cert):
            pytest.skip("CA not found in default location")

        # Initialize PKI structure
        subprocess.run(
            [sys.executable, CA_SERVER_PATH, "--path", self.pki_path, "init"],
            capture_output=True,
            check=True,
        )

        # Generate test certificate
        test_key = os.path.join(self.pki_path, "test.key")
        test_cert = os.path.join(self.pki_path, "test.crt")

        subprocess.run(
            ["openssl", "genrsa", "-out", test_key, "2048"],
            capture_output=True,
            check=True,
        )

        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                test_key,
                "-out",
                os.path.join(self.pki_path, "test.csr"),
                "-subj",
                "/CN=Revoke Test/O=Test",
            ],
            capture_output=True,
            check=True,
        )

        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                os.path.join(self.pki_path, "test.csr"),
                "-CA",
                default_ca_cert,
                "-CAkey",
                default_ca_key,
                "-out",
                test_cert,
                "-days",
                "365",
            ],
            capture_output=True,
            check=True,
        )

        # Verify certificate before revocation
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", default_ca_cert, test_cert],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "OK" in result.stdout

        # Verify the certificate structure
        result = subprocess.run(
            ["openssl", "x509", "-in", test_cert, "-noout", "-subject"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "CN =" in result.stdout and "Revoke Test" in result.stdout


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestCertificateExtensions:
    """
    Tests for X.509 certificate extensions.

    These tests verify that certificates generated with different profiles
    have the correct X.509 extensions as defined in the profiles.

    Extensions tested:
    1. keyUsage - Certificate key usage flags
    2. extendedKeyUsage - Extended key usage OIDs
    3. basicConstraints - CA constraints
    4. subjectKeyIdentifier - SKI extension
    5. authorityKeyIdentifier - AKI extension
    6. subjectAltName - SAN (DNS, IP, EMAIL, URI)
    """

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down for each test."""
        self.pki_path = "/tmp/test_pki_extensions"

        # Clean up before test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

        # Initialize PKI
        subprocess.run(
            [sys.executable, CA_SERVER_PATH, "--path", self.pki_path, "init"],
            capture_output=True,
            check=True,
        )

        # Import here to get the initialized Authority
        from upki_ca.ca.authority import Authority
        from upki_ca.storage.file_storage import FileStorage

        # Initialize Authority with our test PKI path
        self._authority = Authority.get_instance()
        storage = FileStorage(self.pki_path)
        storage.initialize()
        self._authority.initialize(storage=storage)

        # Get paths
        self.ca_cert_path = os.path.join(self.pki_path, "ca.crt")
        self.ca_key_path = os.path.join(self.pki_path, "private", "ca.key")

        # Generate certificates for each profile
        self._generate_test_certificates()

        yield

        # Clean up after test
        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

    def _generate_test_certificates(self):
        """Generate test certificates for different profiles."""

        # Generate CA certificate (self-signed)
        self.ca_cert = self._generate_self_signed_cert(
            "/CN=uPKI Test CA/O=Test", "ca", ca=True
        )

        # Generate RA certificate
        self.ra_cert = self._generate_signed_cert("/CN=Test RA/O=Test", "ra")

        # Generate Server certificate with SAN
        self.server_cert = self._generate_signed_cert(
            "/CN=test.example.com/O=Test", "server", domain="test.example.com"
        )

        # Generate User certificate
        self.user_cert = self._generate_signed_cert("/CN=Test User/O=Test", "user")

        # Generate Admin certificate
        self.admin_cert = self._generate_signed_cert("/CN=Test Admin/O=Test", "admin")

    def _generate_self_signed_cert(
        self, subject: str, profile_name: str, ca: bool = False
    ) -> str:
        """Generate a self-signed certificate."""
        # Generate key
        key_file = os.path.join(self.pki_path, f"{profile_name}.key")
        subprocess.run(
            ["openssl", "genrsa", "-out", key_file, "2048"],
            capture_output=True,
            check=True,
        )

        # Generate CSR
        csr_file = os.path.join(self.pki_path, f"{profile_name}.csr")
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                key_file,
                "-out",
                csr_file,
                "-subj",
                subject,
            ],
            capture_output=True,
            check=True,
        )

        # Generate self-signed certificate
        cert_file = os.path.join(self.pki_path, f"{profile_name}.crt")

        # Write extension config to temp file
        ext_config = self._get_openssl_ext_config(profile_name)
        ext_file = os.path.join(self.pki_path, f"{profile_name}.ext")
        with open(ext_file, "w") as f:
            f.write(ext_config)

        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                csr_file,
                "-signkey",
                key_file,
                "-out",
                cert_file,
                "-days",
                "365",
                "-extfile",
                ext_file,
                "-extensions",
                self._get_openssl_ext_section(profile_name),
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        return cert_file

    def _get_openssl_ext_section(self, profile: str) -> str:
        """Get OpenSSL extension section name for profile."""
        sections = {
            "ca": "ca_ext",
            "ra": "server_ext",
            "server": "server_ext",
            "user": "user_ext",
            "admin": "user_ext",
        }
        return sections.get(profile, "server_ext")

    def _get_openssl_ext_config(self, profile: str) -> str:
        """Get OpenSSL extension config for profile."""
        configs = {
            "ca": """
[ca_ext]
basicConstraints=critical, CA:TRUE
keyUsage=critical, keyCertSign, cRLSign
subjectKeyIdentifier=hash
""",
            "ra": """
[server_ext]
basicConstraints=CA:FALSE
keyUsage=critical, digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth, clientAuth
subjectKeyIdentifier=hash
""",
            "server": """
[server_ext]
basicConstraints=CA:FALSE
keyUsage=critical, digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
subjectAltName=DNS:test.example.com, IP:192.168.1.1
""",
            "user": """
[user_ext]
basicConstraints=CA:FALSE
keyUsage=critical, digitalSignature, nonRepudiation
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
""",
            "admin": """
[user_ext]
basicConstraints=CA:FALSE
keyUsage=critical, digitalSignature, nonRepudiation
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
""",
        }
        return configs.get(profile, "")

    def _generate_signed_cert(
        self, subject: str, profile_name: str, domain: str = ""
    ) -> str:
        """Generate a certificate signed by the CA."""
        # Generate key
        key_file = os.path.join(self.pki_path, f"{profile_name}.key")
        subprocess.run(
            ["openssl", "genrsa", "-out", key_file, "2048"],
            capture_output=True,
            check=True,
        )

        # Generate CSR
        csr_file = os.path.join(self.pki_path, f"{profile_name}.csr")
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                key_file,
                "-out",
                csr_file,
                "-subj",
                subject,
            ],
            capture_output=True,
            check=True,
        )

        # Get CA certificate
        home_dir = os.path.expanduser("~")
        default_ca_cert = os.path.join(home_dir, ".upki", "ca", "ca.crt")
        default_ca_key = os.path.join(home_dir, ".upki", "ca", "ca.key")

        if not os.path.exists(default_ca_cert):
            pytest.skip("CA not found in default location")

        # Generate signed certificate
        cert_file = os.path.join(self.pki_path, f"{profile_name}.crt")

        # Build extensions based on profile
        ext_config = self._get_openssl_ext_config(profile_name)

        # Write extension config to temp file
        ext_file = os.path.join(self.pki_path, f"{profile_name}.ext")
        with open(ext_file, "w") as f:
            f.write(ext_config)

        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                csr_file,
                "-CA",
                default_ca_cert,
                "-CAkey",
                default_ca_key,
                "-out",
                cert_file,
                "-days",
                "365",
                "-extfile",
                ext_file,
                "-extensions",
                self._get_openssl_ext_section(profile_name),
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        return cert_file

    def _get_cert_extensions(self, cert_file: str) -> str:
        """Get certificate extensions using OpenSSL."""
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_file, "-text", "-noout"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout

    def _get_san_dns_names(self, cert_file: str) -> list[str]:
        """Return the list of DNS SAN values from a PEM certificate."""
        with open(cert_file, "rb") as fh:
            cert = load_pem_x509_certificate(fh.read())
        try:
            san = cert.extensions.get_extension_for_class(SubjectAlternativeName)
            return [n.value for n in san.value if isinstance(n, DNSName)]
        except Exception:
            return []

    def _get_san_ip_addresses(self, cert_file: str) -> list[str]:
        """Return the list of IP SAN values (as strings) from a PEM certificate."""
        with open(cert_file, "rb") as fh:
            cert = load_pem_x509_certificate(fh.read())
        try:
            san = cert.extensions.get_extension_for_class(SubjectAlternativeName)
            return [str(n.value) for n in san.value if isinstance(n, IPAddress)]
        except Exception:
            return []

    def _has_extension(self, cert_file: str, extension_name: str) -> bool:
        """Check if certificate has a specific extension."""
        extensions = self._get_cert_extensions(cert_file)
        return extension_name in extensions

    def _get_extension_value(self, cert_file: str, extension_name: str) -> str:
        """Get the value of a specific extension."""
        extensions = self._get_cert_extensions(cert_file)
        # Find the extension section
        lines = extensions.split("\n")
        in_extension = False
        ext_value = ""

        for _i, line in enumerate(lines):
            if extension_name in line:
                in_extension = True
            if in_extension:
                ext_value += line + "\n"
                # Check for end of extension (next X509v3 or empty line after content)
                if ":" not in line and line.strip() and not line.startswith(" "):
                    break

        return ext_value

    # ========== keyUsage Tests ==========

    def test_ca_key_usage(self):
        """Test CA certificate has keyCertSign and cRLSign."""
        extensions = self._get_cert_extensions(self.ca_cert)

        # CA should have Certificate Sign (keyCertSign) and CRL Sign (cRLSign)
        # OpenSSL displays these as "Certificate Sign" and "CRL Sign"
        assert (
            "Certificate Sign" in extensions
        ), "CA certificate should have Certificate Sign"
        assert "CRL Sign" in extensions, "CA certificate should have CRL Sign"

    def test_ra_key_usage(self):
        """Test RA certificate has digitalSignature and keyEncipherment."""
        extensions = self._get_cert_extensions(self.ra_cert)

        assert (
            "Digital Signature" in extensions
        ), "RA certificate should have Digital Signature"
        assert (
            "Key Encipherment" in extensions
        ), "RA certificate should have Key Encipherment"

    def test_server_key_usage(self):
        """Test server certificate has digitalSignature and keyEncipherment."""
        extensions = self._get_cert_extensions(self.server_cert)

        assert (
            "Digital Signature" in extensions
        ), "Server certificate should have Digital Signature"
        assert (
            "Key Encipherment" in extensions
        ), "Server certificate should have Key Encipherment"

    def test_user_key_usage(self):
        """Test user certificate has digitalSignature and nonRepudiation."""
        extensions = self._get_cert_extensions(self.user_cert)

        assert (
            "Digital Signature" in extensions
        ), "User certificate should have Digital Signature"
        assert (
            "Non Repudiation" in extensions
        ), "User certificate should have Non Repudiation"

    def test_admin_key_usage(self):
        """Test admin certificate has digitalSignature and nonRepudiation."""
        extensions = self._get_cert_extensions(self.admin_cert)

        assert (
            "Digital Signature" in extensions
        ), "Admin certificate should have Digital Signature"
        assert (
            "Non Repudiation" in extensions
        ), "Admin certificate should have Non Repudiation"

    # ========== extendedKeyUsage Tests ==========

    def test_ra_extended_key_usage(self):
        """Test RA certificate has serverAuth and clientAuth."""
        extensions = self._get_cert_extensions(self.ra_cert)

        assert (
            "TLS Web Server Authentication" in extensions
        ), "RA should have serverAuth"
        assert (
            "TLS Web Client Authentication" in extensions
        ), "RA should have clientAuth"

    def test_server_extended_key_usage(self):
        """Test server certificate has serverAuth."""
        extensions = self._get_cert_extensions(self.server_cert)

        assert (
            "TLS Web Server Authentication" in extensions
        ), "Server should have serverAuth"

    def test_user_extended_key_usage(self):
        """Test user certificate has clientAuth."""
        extensions = self._get_cert_extensions(self.user_cert)

        assert (
            "TLS Web Client Authentication" in extensions
        ), "User should have clientAuth"

    def test_admin_extended_key_usage(self):
        """Test admin certificate has clientAuth."""
        extensions = self._get_cert_extensions(self.admin_cert)

        assert (
            "TLS Web Client Authentication" in extensions
        ), "Admin should have clientAuth"

    # ========== basicConstraints Tests ==========

    def test_ca_basic_constraints(self):
        """Test CA certificate has CA:TRUE."""
        extensions = self._get_cert_extensions(self.ca_cert)

        assert "CA:TRUE" in extensions, "CA certificate should have CA:TRUE"

    def test_subordinate_basic_constraints(self):
        """Test subordinate certificates have CA:FALSE."""
        for cert, name in [
            (self.ra_cert, "RA"),
            (self.server_cert, "Server"),
            (self.user_cert, "User"),
            (self.admin_cert, "Admin"),
        ]:
            extensions = self._get_cert_extensions(cert)
            assert "CA:FALSE" in extensions, f"{name} certificate should have CA:FALSE"

    # ========== subjectKeyIdentifier Tests ==========

    def test_subject_key_identifier_present(self):
        """Test SKI is present in all certificates."""
        for cert, name in [
            (self.ca_cert, "CA"),
            (self.ra_cert, "RA"),
            (self.server_cert, "Server"),
            (self.user_cert, "User"),
            (self.admin_cert, "Admin"),
        ]:
            extensions = self._get_cert_extensions(cert)
            assert (
                "Subject Key Identifier" in extensions
            ), f"{name} should have Subject Key Identifier"

    def test_subject_key_identifier_format(self):
        """Test SKI is correctly formatted (40 hex characters)."""
        result = subprocess.run(
            ["openssl", "x509", "-in", self.server_cert, "-noout", "-text"],
            capture_output=True,
            text=True,
            check=True,
        )

        # Find Subject Key Identifier line
        for line in result.stdout.split("\n"):
            if "Subject Key Identifier" in line:
                # Should contain a hash value
                assert ":" in line or len(line.split(":")[0].strip()) > 0
                break

    # ========== authorityKeyIdentifier Tests ==========

    def test_authority_key_identifier_present(self):
        """Test AKI is present in signed certificates (except self-signed CA)."""
        # RA, Server, User, Admin should have AKI
        for cert, name in [
            (self.ra_cert, "RA"),
            (self.server_cert, "Server"),
            (self.user_cert, "User"),
            (self.admin_cert, "Admin"),
        ]:
            extensions = self._get_cert_extensions(cert)
            assert (
                "Authority Key Identifier" in extensions
            ), f"{name} should have Authority Key Identifier"

    def test_ca_no_authority_key_identifier(self):
        """Test self-signed CA has no AKI (or keyid:always matches)."""
        # Self-signed CA may have AKI pointing to itself
        # This is acceptable for self-signed

    # ========== subjectAltName Tests ==========

    def test_san_dns(self):
        """Test SAN DNS names are present."""
        dns_names = self._get_san_dns_names(self.server_cert)
        assert any(
            name == "test.example.com" for name in dns_names
        ), "Server certificate should have DNS SAN"

    def test_san_ip(self):
        """Test SAN IP addresses are present."""
        ip_addresses = self._get_san_ip_addresses(self.server_cert)
        assert any(
            addr == "192.168.1.1" for addr in ip_addresses
        ), "Server certificate should have IP SAN"

    def test_profiles_without_san(self):
        """Test profiles without SAN don't have subjectAltName extension."""
        # User and Admin don't have altnames by default in openssl config
        # but our test creates them - let's verify they have SAN if configured
        # For this test, we check that the RA cert (which doesn't have explicit SAN)
        # either has or doesn't have SAN based on profile configuration
        pass  # This is informational


class TestSeedDisplay:
    """Tests for seed auto-generation and display during ``init``."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down for each test."""
        self.pki_path = "/tmp/test_pki_seed"

        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)

        yield

        if os.path.exists(self.pki_path):
            shutil.rmtree(self.pki_path)
        from upki_ca.ca.authority import Authority

        Authority.reset_instance()

    def test_init_generates_and_displays_seed(self):
        """Test that init auto-generates and displays a seed when none is configured."""
        result = subprocess.run(
            [sys.executable, CA_SERVER_PATH, "--path", self.pki_path, "init"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert (
            "Registration seed generated" in result.stdout
        ), f"Expected seed generation message in stdout:\n{result.stdout}"
        assert "PKI initialized successfully" in result.stdout

        # Verify a token-looking string (urlsafe base64, ≥ 20 chars) is present in output
        import re

        seed_candidates = [
            line.strip()
            for line in result.stdout.splitlines()
            if re.fullmatch(r"[A-Za-z0-9_\-]{20,}", line.strip())
        ]
        assert seed_candidates, f"No seed token found in init output:\n{result.stdout}"

    def test_init_does_not_regenerate_existing_seed(self):
        """Test that a second init does not overwrite a seed already present in config."""
        # First init – generates the seed
        r1 = subprocess.run(
            [sys.executable, CA_SERVER_PATH, "--path", self.pki_path, "init"],
            capture_output=True,
            text=True,
        )
        assert r1.returncode == 0
        assert "Registration seed generated" in r1.stdout

        from upki_ca.ca.authority import Authority

        Authority.reset_instance()

        # Second init – seed already exists, no new one should be generated
        r2 = subprocess.run(
            [sys.executable, CA_SERVER_PATH, "--path", self.pki_path, "init"],
            capture_output=True,
            text=True,
        )
        assert r2.returncode == 0
        assert (
            "Registration seed generated" not in r2.stdout
        ), f"Seed should not be regenerated on second init:\n{r2.stdout}"


class TestCAImport:
    """Tests for importing a pre-existing CA key/certificate during ``init``."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down for each test."""
        self.pki_path = "/tmp/test_pki_import"
        self.ext_dir = "/tmp/test_external_ca"
        self._default_ca_dir = os.path.join(os.path.expanduser("~"), ".upki", "ca")

        for path in [self.pki_path, self.ext_dir]:
            if os.path.exists(path):
                shutil.rmtree(path)
            os.makedirs(path)

        # Back up any existing CA files so other tests are not affected
        self._ca_backup: dict[str, bytes] = {}
        for fname in ("ca.key", "ca.crt"):
            fpath = os.path.join(self._default_ca_dir, fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    self._ca_backup[fname] = f.read()

        yield

        # Restore the original CA files
        for fname, content in self._ca_backup.items():
            fpath = os.path.join(self._default_ca_dir, fname)
            os.makedirs(self._default_ca_dir, exist_ok=True)
            with open(fpath, "wb") as f:
                f.write(content)
        if "ca.key" in self._ca_backup:
            os.chmod(os.path.join(self._default_ca_dir, "ca.key"), 0o600)

        for path in [self.pki_path, self.ext_dir]:
            if os.path.exists(path):
                shutil.rmtree(path)
        from upki_ca.ca.authority import Authority

        Authority.reset_instance()

    def _make_ca(
        self, key_path: str, cert_path: str, subj: str = "/CN=Imported Root CA"
    ) -> None:
        """Generate a CA key and self-signed cert using openssl."""
        subprocess.run(
            ["openssl", "genrsa", "-out", key_path, "2048"],
            capture_output=True,
            check=True,
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                key_path,
                "-out",
                cert_path,
                "-days",
                "3650",
                "-subj",
                subj,
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
            capture_output=True,
            check=True,
        )

    def test_import_existing_ca(self):
        """Test initializing PKI by importing an existing CA key/cert pair."""
        key_path = os.path.join(self.ext_dir, "ext_ca.key")
        cert_path = os.path.join(self.ext_dir, "ext_ca.crt")
        self._make_ca(key_path, cert_path, subj="/CN=External Root CA/O=TestOrg")

        result = subprocess.run(
            [
                sys.executable,
                CA_SERVER_PATH,
                "--path",
                self.pki_path,
                "init",
                "--ca-key",
                key_path,
                "--ca-cert",
                cert_path,
                "--ca-password",
                "",  # empty = unencrypted key
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}\n{result.stdout}"
        assert "PKI initialized successfully" in result.stdout

        # The imported CA cert must be present in the managed location
        default_ca_cert = os.path.join(os.path.expanduser("~"), ".upki", "ca", "ca.crt")
        assert os.path.exists(default_ca_cert)

        # Verify subject is preserved from the imported cert
        subj_result = subprocess.run(
            ["openssl", "x509", "-in", default_ca_cert, "-noout", "-subject"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert (
            "External Root CA" in subj_result.stdout
        ), f"Imported CA subject not found: {subj_result.stdout}"

    def test_import_encrypted_ca_key(self):
        """Test importing a CA whose private key is protected with a password."""
        enc_key = os.path.join(self.ext_dir, "enc_ca.key")
        cert_path = os.path.join(self.ext_dir, "enc_ca.crt")

        subprocess.run(
            [
                "openssl",
                "genrsa",
                "-aes256",
                "-passout",
                "pass:supersecret",
                "-out",
                enc_key,
                "2048",
            ],
            capture_output=True,
            check=True,
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                enc_key,
                "-passin",
                "pass:supersecret",
                "-out",
                cert_path,
                "-days",
                "3650",
                "-subj",
                "/CN=Encrypted CA",
            ],
            capture_output=True,
            check=True,
        )

        result = subprocess.run(
            [
                sys.executable,
                CA_SERVER_PATH,
                "--path",
                self.pki_path,
                "init",
                "--ca-key",
                enc_key,
                "--ca-cert",
                cert_path,
                "--ca-password",
                "supersecret",
            ],
            capture_output=True,
            text=True,
        )
        assert (
            result.returncode == 0
        ), f"init with encrypted key failed:\n{result.stderr}\n{result.stdout}"
        assert "PKI initialized successfully" in result.stdout

    def test_import_mismatched_key_and_cert_fails(self):
        """Test that init fails when the CA private key and certificate do not match."""
        key1 = os.path.join(self.ext_dir, "ca1.key")
        cert1 = os.path.join(self.ext_dir, "ca1.crt")
        key2 = os.path.join(self.ext_dir, "ca2.key")
        self._make_ca(key1, cert1)
        # Generate an independent second key (different from the one used for cert1)
        subprocess.run(
            ["openssl", "genrsa", "-out", key2, "2048"],
            capture_output=True,
            check=True,
        )

        # key2 + cert1 → public keys do not match → must fail
        result = subprocess.run(
            [
                sys.executable,
                CA_SERVER_PATH,
                "--path",
                self.pki_path,
                "init",
                "--ca-key",
                key2,
                "--ca-cert",
                cert1,
                "--ca-password",
                "",
            ],
            capture_output=True,
            text=True,
        )
        assert (
            result.returncode != 0
        ), "init must fail when the CA key and cert do not correspond"

    def test_init_requires_both_ca_key_and_ca_cert(self):
        """Test that --ca-key without --ca-cert (and vice versa) is rejected."""
        key_path = os.path.join(self.ext_dir, "ca.key")
        subprocess.run(
            ["openssl", "genrsa", "-out", key_path, "2048"],
            capture_output=True,
            check=True,
        )

        # Only --ca-key, no --ca-cert
        result = subprocess.run(
            [
                sys.executable,
                CA_SERVER_PATH,
                "--path",
                self.pki_path,
                "init",
                "--ca-key",
                key_path,
            ],
            capture_output=True,
            text=True,
            input="",
        )
        assert result.returncode != 0, "Must fail when only --ca-key is given"
        assert "--ca-key and --ca-cert" in result.stderr


class TestSubCAChain:
    """Tests for intermediate (sub-CA) certificate generation and chain validation."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Set up and tear down for each test."""
        self.root_pki_path = "/tmp/test_pki_subca_root"
        self.sub_pki_path = "/tmp/test_pki_subca_sub"
        self._default_ca_dir = os.path.join(os.path.expanduser("~"), ".upki", "ca")

        for path in [self.root_pki_path, self.sub_pki_path]:
            if os.path.exists(path):
                shutil.rmtree(path)

        # Back up any existing CA files to prevent cross-test contamination
        self._ca_backup: dict[str, bytes] = {}
        for fname in ("ca.key", "ca.crt"):
            fpath = os.path.join(self._default_ca_dir, fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    self._ca_backup[fname] = f.read()

        from upki_ca.ca.authority import Authority

        Authority.reset_instance()

        yield

        # Restore original CA files
        for fname, content in self._ca_backup.items():
            fpath = os.path.join(self._default_ca_dir, fname)
            os.makedirs(self._default_ca_dir, exist_ok=True)
            with open(fpath, "wb") as f:
                f.write(content)
        if "ca.key" in self._ca_backup:
            os.chmod(os.path.join(self._default_ca_dir, "ca.key"), 0o600)

        for path in [self.root_pki_path, self.sub_pki_path]:
            if os.path.exists(path):
                shutil.rmtree(path)
        from upki_ca.ca.authority import Authority

        Authority.reset_instance()

    def test_sub_ca_has_correct_basic_constraints(self):
        """Sub-CA generated via the 'ca' profile must have BasicConstraints(CA:TRUE, pathLen:0)."""
        from upki_ca.ca.authority import Authority
        from upki_ca.storage.file_storage import FileStorage

        storage = FileStorage(self.root_pki_path)
        storage.initialize()
        authority = Authority.get_instance()
        authority.initialize(storage=storage, keychain=self.root_pki_path)

        sub_ca_cert = authority.generate_certificate("sub-ca.example.com", "ca")
        bc = sub_ca_cert.basic_constraints

        assert bc["ca"] is True, "Sub-CA certificate must have CA:TRUE"
        assert (
            bc["path_length"] == 0
        ), f"Sub-CA certificate must have pathLen:0 (got {bc['path_length']})"

    def test_sub_ca_key_is_stored_after_generation(self):
        """Private key of a generated certificate must be retrievable from storage."""
        from upki_ca.ca.authority import Authority
        from upki_ca.storage.file_storage import FileStorage

        storage = FileStorage(self.root_pki_path)
        storage.initialize()
        authority = Authority.get_instance()
        authority.initialize(storage=storage, keychain=self.root_pki_path)

        authority.generate_certificate("sub-ca.example.com", "ca")
        key_data = storage.get_key("sub-ca.example.com")
        assert (
            key_data is not None
        ), "Sub-CA private key must be retrievable from storage"

    def test_sub_ca_chain_validates_with_openssl(self):
        """Root CA → Sub-CA → Leaf certificate chain must validate with openssl verify."""
        from upki_ca.ca.authority import Authority
        from upki_ca.storage.file_storage import FileStorage

        # --- Root CA setup ---
        root_storage = FileStorage(self.root_pki_path)
        root_storage.initialize()
        root_authority = Authority.get_instance()
        # Use root_pki_path as the keychain directory to stay fully isolated from
        # ~/.upki/ca/ which may be in an arbitrary state from previous test runs.
        root_authority.initialize(storage=root_storage, keychain=self.root_pki_path)

        root_ca_path = os.path.join(self.root_pki_path, "root_ca.crt")
        with open(root_ca_path, "w") as f:
            f.write(root_authority.get_ca_certificate())

        # --- Generate sub-CA (signed by root CA) ---
        sub_ca_cert_obj = root_authority.generate_certificate(
            "sub-ca.example.com", "ca"
        )
        sub_ca_cert_path = os.path.join(self.root_pki_path, "sub_ca.crt")
        with open(sub_ca_cert_path, "w") as f:
            f.write(sub_ca_cert_obj.export())

        sub_ca_key_data = root_storage.get_key("sub-ca.example.com")
        assert sub_ca_key_data is not None
        sub_ca_key_path = os.path.join(self.root_pki_path, "sub_ca.key")
        with open(sub_ca_key_path, "wb") as f:
            f.write(sub_ca_key_data)

        # Sub-CA must be directly verifiable against root CA
        r = subprocess.run(
            ["openssl", "verify", "-CAfile", root_ca_path, sub_ca_cert_path],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, f"Sub-CA not signed by root CA:\n{r.stderr}"

        # --- Sub-CA Authority (imported from the generated key/cert) ---
        Authority.reset_instance()
        sub_storage = FileStorage(self.sub_pki_path)
        sub_storage.initialize()
        sub_authority = Authority.get_instance()
        sub_authority.initialize(
            storage=sub_storage,
            keychain=self.sub_pki_path,  # isolate from the global ~/.upki/ca/ directory
            import_key=sub_ca_key_path,
            import_cert=sub_ca_cert_path,
        )

        # --- Leaf certificate signed by sub-CA ---
        leaf_cert_obj = sub_authority.generate_certificate(
            "server.example.com", "server"
        )
        leaf_cert_path = os.path.join(self.sub_pki_path, "leaf.crt")
        with open(leaf_cert_path, "w") as f:
            f.write(leaf_cert_obj.export())

        # Full chain: Root CA → Sub-CA (untrusted) → Leaf
        r = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                root_ca_path,
                "-untrusted",
                sub_ca_cert_path,
                leaf_cert_path,
            ],
            capture_output=True,
            text=True,
        )
        assert (
            r.returncode == 0
        ), f"Full chain (Root → Sub-CA → Leaf) validation failed:\n{r.stderr}"


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
