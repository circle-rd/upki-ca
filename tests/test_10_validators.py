"""
Unit tests for validators.

Author: uPKI Team
License: MIT
"""

import pytest

from upki_ca.core.upki_error import ValidationError
from upki_ca.core.validators import (
    DNValidator,
    FQDNValidator,
    RevokeReasonValidator,
    SANValidator,
)


class TestFQDNValidator:
    """Tests for FQDNValidator."""

    def test_valid_fqdn(self):
        """Test valid FQDNs."""
        assert FQDNValidator.validate("example.com") is True
        assert FQDNValidator.validate("sub.example.com") is True
        assert FQDNValidator.validate("test-server.example.com") is True

    def test_invalid_empty(self):
        """Test empty FQDN."""
        with pytest.raises(ValidationError):
            FQDNValidator.validate("")

    def test_too_long(self):
        """Test too long FQDN."""
        long_domain = "a" * 254 + ".com"
        with pytest.raises(ValidationError):
            FQDNValidator.validate(long_domain)

    def test_blocked_domains(self):
        """Test blocked domains."""
        with pytest.raises(ValidationError):
            FQDNValidator.validate("localhost")
        with pytest.raises(ValidationError):
            FQDNValidator.validate("local")

    def test_label_too_long(self):
        """Test label too long."""
        long_label = "a" * 64 + ".com"
        with pytest.raises(ValidationError):
            FQDNValidator.validate(long_label)

    def test_wildcard(self):
        """Test wildcard domains."""
        assert FQDNValidator.validate("*.example.com") is True


class TestSANValidator:
    """Tests for SANValidator."""

    def test_valid_dns(self):
        """Test valid DNS SAN."""
        san = {"type": "DNS", "value": "example.com"}
        assert SANValidator.validate(san) is True

    def test_valid_ip(self):
        """Test valid IP SAN."""
        san = {"type": "IP", "value": "192.168.1.1"}
        assert SANValidator.validate(san) is True

    def test_valid_email(self):
        """Test valid email SAN."""
        san = {"type": "EMAIL", "value": "test@example.com"}
        assert SANValidator.validate(san) is True

    def test_invalid_type(self):
        """Test invalid SAN type."""
        san = {"type": "INVALID", "value": "test"}
        with pytest.raises(ValidationError):
            SANValidator.validate(san)

    def test_empty_value(self):
        """Test empty SAN value."""
        san = {"type": "DNS", "value": ""}
        with pytest.raises(ValidationError):
            SANValidator.validate(san)

    def test_sanitize(self):
        """Test SAN sanitization."""
        sans = [
            {"type": "DNS", "value": "example.com "},
            {"type": "DNS", "value": "test.com"},
        ]
        result = SANValidator.sanitize(sans)
        assert len(result) == 2
        assert result[0]["value"] == "example.com"


class TestDNValidator:
    """Tests for DNValidator."""

    def test_valid_dn(self):
        """Test valid DN."""
        dn = {"CN": "test.example.com", "O": "Company"}
        assert DNValidator.validate(dn) is True

    def test_missing_cn(self):
        """Test missing CN."""
        dn = {"O": "Company"}
        with pytest.raises(ValidationError):
            DNValidator.validate(dn)

    def test_empty_cn(self):
        """Test empty CN."""
        dn = {"CN": ""}
        with pytest.raises(ValidationError):
            DNValidator.validate(dn)

    def test_valid_cn(self):
        """Test CN validation."""
        assert DNValidator.validate_cn("test.example.com") is True
        # Test CN with spaces (the main fix)
        assert DNValidator.validate_cn("uPKI Root CA") is True
        assert DNValidator.validate_cn("Test CA (Secure)") is True
        assert DNValidator.validate_cn("Company's Root CA") is True
        with pytest.raises(ValidationError):
            DNValidator.validate_cn("")

    def test_cn_too_long(self):
        """Test CN too long."""
        long_cn = "a" * 65
        with pytest.raises(ValidationError):
            DNValidator.validate_cn(long_cn)


class TestRevokeReasonValidator:
    """Tests for RevokeReasonValidator."""

    def test_valid_reason(self):
        """Test valid revocation reason."""
        assert RevokeReasonValidator.validate("unspecified") is True
        assert RevokeReasonValidator.validate("keyCompromise") is True
        assert RevokeReasonValidator.validate("cACompromise") is True

    def test_invalid_reason(self):
        """Test invalid revocation reason."""
        with pytest.raises(ValidationError):
            RevokeReasonValidator.validate("invalid_reason")

    def test_empty_reason(self):
        """Test empty reason."""
        with pytest.raises(ValidationError):
            RevokeReasonValidator.validate("")
