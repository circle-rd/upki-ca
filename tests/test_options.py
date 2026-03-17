# -*- coding: utf-8 -*-

"""
Unit tests for upkica.core.options module.
"""

import pytest
from upkica.core.options import Options


class TestOptions:
    """Test cases for Options class."""

    def test_options_initialization(self):
        """Test Options initialization with default values."""
        opts = Options()
        assert opts.KeyLen == [1024, 2048, 4096]
        assert opts.CertTypes == ["user", "server", "email", "sslCA"]
        assert opts.Digest == ["md5", "sha1", "sha256", "sha512"]

    def test_options_str_representation(self):
        """Test string representation of Options."""
        opts = Options()
        opts_str = str(opts)
        assert "KeyLen" in opts_str
        assert "CertTypes" in opts_str

    def test_options_json_default(self):
        """Test JSON output with default formatting."""
        opts = Options()
        json_str = opts.json()
        assert "KeyLen" in json_str
        assert "CertTypes" in json_str

    def test_options_json_minimize(self):
        """Test JSON output with minimize=True."""
        opts = Options()
        json_str = opts.json(minimize=True)
        assert "KeyLen" in json_str
        # Minimized JSON should not have indentation
        assert "\n" not in json_str

    def test_clean_valid_keytype(self):
        """Test clean method with valid key type."""
        opts = Options()
        result = opts.clean("rsa", "KeyTypes")
        assert result == "rsa"

    def test_clean_valid_keylen(self):
        """Test clean method with valid key length."""
        opts = Options()
        result = opts.clean(2048, "KeyLen")
        assert result == 2048

    def test_clean_valid_digest(self):
        """Test clean method with valid digest."""
        opts = Options()
        result = opts.clean("sha256", "Digest")
        assert result == "sha256"

    def test_clean_invalid_value_raises(self):
        """Test clean method with invalid value."""
        opts = Options()
        with pytest.raises(ValueError, match="Invalid value"):
            opts.clean("invalid_key", "KeyTypes")

    def test_clean_null_data_raises(self):
        """Test clean method with None data."""
        opts = Options()
        with pytest.raises(ValueError, match="Null data"):
            opts.clean(None, "KeyTypes")

    def test_clean_null_field_raises(self):
        """Test clean method with None field."""
        opts = Options()
        with pytest.raises(ValueError, match="Null field"):
            opts.clean("rsa", None)

    def test_clean_unsupported_field_raises(self):
        """Test clean method with unsupported field."""
        opts = Options()
        with pytest.raises(NotImplementedError, match="Unsupported field"):
            opts.clean("rsa", "InvalidField")

    def test_allowed_key_types(self):
        """Test allowed key types."""
        opts = Options()
        assert "rsa" in opts.KeyTypes
        assert "dsa" in opts.KeyTypes

    def test_allowed_certificate_types(self):
        """Test allowed certificate types."""
        opts = Options()
        assert "user" in opts.CertTypes
        assert "server" in opts.CertTypes
        assert "email" in opts.CertTypes
        assert "sslCA" in opts.CertTypes

    def test_allowed_digest_algorithms(self):
        """Test allowed digest algorithms."""
        opts = Options()
        assert "md5" in opts.Digest
        assert "sha1" in opts.Digest
        assert "sha256" in opts.Digest
        assert "sha512" in opts.Digest

    def test_allowed_x509_fields(self):
        """Test allowed X.509 subject fields."""
        opts = Options()
        assert "C" in opts.Fields
        assert "ST" in opts.Fields
        assert "L" in opts.Fields
        assert "O" in opts.Fields
        assert "OU" in opts.Fields
        assert "CN" in opts.Fields
        assert "emailAddress" in opts.Fields

    def test_allowed_key_usages(self):
        """Test allowed key usage flags."""
        opts = Options()
        assert "digitalSignature" in opts.Usages
        assert "keyEncipherment" in opts.Usages
        assert "keyCertSign" in opts.Usages
        assert "cRLSign" in opts.Usages

    def test_allowed_extended_usages(self):
        """Test allowed extended key usages."""
        opts = Options()
        assert "serverAuth" in opts.ExtendedUsages
        assert "clientAuth" in opts.ExtendedUsages
        assert "OCSPSigning" in opts.ExtendedUsages
