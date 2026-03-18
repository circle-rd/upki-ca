"""
Unit tests for Profiles.

Author: uPKI Team
License: MIT
"""

import pytest

from upki_ca.core.upki_error import ProfileError
from upki_ca.utils.profiles import Profiles


class TestProfiles:
    """Tests for Profiles class."""

    def test_default_profiles(self):
        """Test default profiles are loaded."""
        profiles = Profiles()
        profiles.load()

        # Check built-in profiles exist
        assert "ca" in profiles.list()
        assert "ra" in profiles.list()
        assert "server" in profiles.list()
        assert "user" in profiles.list()
        assert "admin" in profiles.list()

    def test_get_profile(self):
        """Test getting a profile."""
        profiles = Profiles()
        profiles.load()

        ca_profile = profiles.get("ca")
        assert ca_profile is not None
        assert ca_profile["keyType"] == "rsa"
        assert ca_profile["keyLen"] == 4096

    def test_get_nonexistent_profile(self):
        """Test getting nonexistent profile."""
        profiles = Profiles()
        profiles.load()

        with pytest.raises(ProfileError):
            profiles.get("nonexistent")

    def test_add_profile(self):
        """Test adding a new profile."""
        profiles = Profiles()
        profiles.load()

        new_profile = {
            "keyType": "rsa",
            "keyLen": 2048,
            "duration": 30,
            "digest": "sha256",
            "subject": {"CN": "test"},
            "keyUsage": ["digitalSignature"],
            "extendedKeyUsage": [],
            "certType": "user",
        }

        assert profiles.add("test_profile", new_profile) is True
        assert "test_profile" in profiles.list()

    def test_add_builtin_profile_fails(self):
        """Test adding built-in profile fails."""
        profiles = Profiles()
        profiles.load()

        with pytest.raises(ProfileError):
            profiles.add("ca", {"keyType": "rsa"})

    def test_remove_builtin_profile_fails(self):
        """Test removing built-in profile fails."""
        profiles = Profiles()
        profiles.load()

        with pytest.raises(ProfileError):
            profiles.remove("ca")

    def test_validate_profile_valid(self):
        """Test profile validation with valid data."""
        profiles = Profiles()

        valid_profile = {
            "keyType": "rsa",
            "keyLen": 2048,
            "duration": 30,
            "digest": "sha256",
            "subject": {"CN": "test"},
            "keyUsage": ["digitalSignature"],
            "extendedKeyUsage": [],
            "certType": "user",
        }

        assert profiles._validate_profile(valid_profile) is True

    def test_validate_profile_invalid_key_type(self):
        """Test profile validation with invalid key type."""
        profiles = Profiles()

        invalid_profile = {
            "keyType": "invalid",
            "keyLen": 2048,
            "duration": 30,
            "digest": "sha256",
            "subject": {"CN": "test"},
            "keyUsage": [],
            "extendedKeyUsage": [],
            "certType": "user",
        }

        with pytest.raises(ProfileError):
            profiles._validate_profile(invalid_profile)

    def test_validate_profile_invalid_key_len(self):
        """Test profile validation with invalid key length."""
        profiles = Profiles()

        invalid_profile = {
            "keyType": "rsa",
            "keyLen": 1234,
            "duration": 30,
            "digest": "sha256",
            "subject": {"CN": "test"},
            "keyUsage": [],
            "extendedKeyUsage": [],
            "certType": "user",
        }

        with pytest.raises(ProfileError):
            profiles._validate_profile(invalid_profile)

    def test_validate_profile_invalid_digest(self):
        """Test profile validation with invalid digest."""
        profiles = Profiles()

        invalid_profile = {
            "keyType": "rsa",
            "keyLen": 2048,
            "duration": 30,
            "digest": "invalid",
            "subject": {"CN": "test"},
            "keyUsage": [],
            "extendedKeyUsage": [],
            "certType": "user",
        }

        with pytest.raises(ProfileError):
            profiles._validate_profile(invalid_profile)

    def test_validate_profile_missing_subject(self):
        """Test profile validation with missing subject."""
        profiles = Profiles()

        invalid_profile = {
            "keyType": "rsa",
            "keyLen": 2048,
            "duration": 30,
            "digest": "sha256",
            "subject": {},
            "keyUsage": [],
            "extendedKeyUsage": [],
            "certType": "user",
        }

        with pytest.raises(ProfileError):
            profiles._validate_profile(invalid_profile)
