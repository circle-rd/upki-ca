# -*- coding: utf-8 -*-

"""
Unit tests for upkica.core.upkiError module.
"""

import pytest
from upkica.core.upkiError import UPKIError


class TestUPKIError:
    """Test cases for UPKIError exception class."""

    def test_error_creation_with_code_and_reason(self):
        """Test creating error with code and reason."""
        err = UPKIError(404, "Certificate not found")
        assert err.code == 404
        assert err.reason == "Certificate not found"

    def test_error_creation_with_default_values(self):
        """Test creating error with default values."""
        err = UPKIError()
        assert err.code == 0
        assert err.reason == ""

    def test_error_creation_with_reason_only(self):
        """Test creating error with reason only."""
        err = UPKIError(reason="Something went wrong")
        assert err.code == 0
        assert err.reason == "Something went wrong"

    def test_error_str_representation(self):
        """Test string representation of error."""
        err = UPKIError(500, "Internal server error")
        assert str(err) == "Error [500]: Internal server error"

    def test_error_repr_representation(self):
        """Test repr representation of error."""
        err = UPKIError(500, "Internal server error")
        assert repr(err) == "UPKIError(code=500, reason='Internal server error')"

    def test_error_with_exception_reason(self):
        """Test creating error with Exception as reason."""
        original_err = ValueError("Invalid value")
        err = UPKIError(1, original_err)
        assert err.code == 1
        assert err.reason == "Invalid value"

    def test_invalid_code_raises_error(self):
        """Test that invalid code raises ValueError."""
        with pytest.raises(ValueError, match="Invalid error code"):
            UPKIError("not_a_number", "test")

    def test_error_equality(self):
        """Test error equality."""
        err1 = UPKIError(1, "test")
        err2 = UPKIError(1, "test")
        assert err1.code == err2.code
        assert err1.reason == err2.reason
