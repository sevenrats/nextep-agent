"""Shared fixtures: ephemeral self-signed certs for flow-plumbing tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_self_signed(
    cn: str = "svc.example.com",
    sans: list[str] | None = None,
    lifetime_days: int = 90,
) -> tuple[str, str, datetime]:
    """Return (cert_pem, key_pem, not_after) for a throwaway leaf."""
    sans = sans if sans is not None else [cn]
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=lifetime_days)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, not_after


@pytest.fixture
def self_signed():
    return make_self_signed
