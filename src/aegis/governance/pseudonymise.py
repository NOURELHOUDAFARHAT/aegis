"""Pseudonymisation of personal data before it leaves AEGIS.

WHICH DATA IS PERSONAL
----------------------
An IP address that connected to the honeypot is personal data under the GDPR:
it can identify a person or household, and AEGIS collected it first-hand.
Indicators published by threat feeds (a Feodo C2 server, a URLhaus host) were
already published by their sources for sharing; they are not re-identified here.

WHY A KEYED HASH, NOT A PLAIN ONE
---------------------------------
There are only about 4.3 billion IPv4 addresses. Hashing every one of them with
SHA-256 takes minutes on a laptop, so a plain hash of an IP is reversible by
simply trying them all. HMAC-SHA256 with a secret key is not: without the key
there is nothing to try against. The same address always maps to the same
pseudonym, so "this attacker came back 40 times" stays visible.

The key comes from AEGIS_PSEUDONYMISATION_KEY - a GitHub Actions secret in
deployment - and is never written anywhere AEGIS publishes.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Mapping

KEY_ENV = "AEGIS_PSEUDONYMISATION_KEY"
MIN_KEY_BYTES = 32

# Four dot-separated groups of 1-3 digits, not glued to other digits or dots, so
# version strings like "SSH-2.0-OpenSSH_9.2" or "1.2.3.4.5" do not match.
_IPV4_SHAPE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


class PseudonymisationKeyError(Exception):
    """The key is missing where required, or too short to be safe."""


def load_key(environ: Mapping[str, str] | None = None) -> bytes | None:
    """The pseudonymisation key, or None when it is not configured."""
    raw = (environ if environ is not None else os.environ).get(KEY_ENV, "")
    if not raw:
        return None
    key = raw.encode("utf-8")
    if len(key) < MIN_KEY_BYTES:
        raise PseudonymisationKeyError(
            f"{KEY_ENV} must be at least {MIN_KEY_BYTES} bytes; a short key can be guessed."
        )
    return key


def pseudonymise_ip(ip: str, key: bytes) -> str:
    """A stable, non-reversible stand-in for an IP address. Raises ValueError if it is not one."""
    normalised = str(ipaddress.ip_address(ip.strip()))
    digest = hmac.new(key, normalised.encode("ascii"), hashlib.sha256).hexdigest()
    return f"anon-{digest[:16]}"


def _is_ipv4(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
    except ValueError:
        return False
    return True


def find_ipv4(text: str) -> list[str]:
    """Every valid IPv4 address appearing anywhere in a piece of text."""
    return [match for match in _IPV4_SHAPE.findall(text) if _is_ipv4(match)]


def redact_ips(text: str | None) -> str | None:
    """Replace IPv4 addresses inside free text, e.g. a command an attacker typed."""
    if text is None:
        return None
    return _IPV4_SHAPE.sub(lambda m: "[ip]" if _is_ipv4(m.group(0)) else m.group(0), text)
