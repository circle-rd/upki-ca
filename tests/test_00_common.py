"""
Unit tests for Common class.

Author: uPKI Team
License: MIT
"""

import pytest

from upkica.core.common import Common


class TestCommon:
    """Tests for Common class."""

    def test_timestamp(self):
        """Test timestamp generation."""
        ts = Common.timestamp()
        assert ts is not None
        assert "T" in ts  # ISO format contains T

    def test_get_home_dir(self):
        """Test getting home directory."""
        home = Common.get_home_dir()
        assert home is not None
        assert len(home) > 0

    def test_get_upki_dir(self):
        """Test getting uPKI directory."""
        upki_dir = Common.get_upki_dir()
        assert upki_dir is not None
        assert ".upki" in upki_dir

    def test_get_ca_dir(self):
        """Test getting CA directory."""
        ca_dir = Common.get_ca_dir()
        assert ca_dir is not None
        assert "ca" in ca_dir

    def test_parse_dn(self):
        """Test DN parsing."""
        dn = "/C=FR/O=Company/CN=example.com"
        result = Common.parse_dn(dn)

        assert result["C"] == "FR"
        assert result["O"] == "Company"
        assert result["CN"] == "example.com"

    def test_parse_dn_without_slashes(self):
        """Test DN parsing without leading slash."""
        dn = "C=FR/O=Company/CN=example.com"
        result = Common.parse_dn(dn)

        assert result["C"] == "FR"
        assert result["CN"] == "example.com"

    def test_build_dn(self):
        """Test DN building."""
        components = {"C": "FR", "O": "Company", "CN": "example.com"}
        result = Common.build_dn(components)

        assert "/C=FR" in result
        assert "/O=Company" in result
        assert "/CN=example.com" in result

    def test_validate_key_type(self):
        """Test key type validation."""
        assert Common.validate_key_type("rsa") is True
        assert Common.validate_key_type("dsa") is True
        assert Common.validate_key_type("invalid") is False

    def test_validate_key_length(self):
        """Test key length validation."""
        assert Common.validate_key_length(1024) is True
        assert Common.validate_key_length(2048) is True
        assert Common.validate_key_length(4096) is True
        assert Common.validate_key_length(512) is False
        assert Common.validate_key_length(8192) is False

    def test_validate_digest(self):
        """Test digest validation."""
        assert Common.validate_digest("md5") is True
        assert Common.validate_digest("sha1") is True
        assert Common.validate_digest("sha256") is True
        assert Common.validate_digest("sha512") is True
        assert Common.validate_digest("invalid") is False

    def test_sanitize_dn(self):
        """Test DN sanitization."""
        # Should remove null bytes
        dn = "CN=test\x00"
        result = Common.sanitize_dn(dn)
        assert "\x00" not in result
