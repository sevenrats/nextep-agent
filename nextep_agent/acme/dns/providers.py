"""Provider configuration dataclasses for dns-lexicon backed DNS handlers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class _BaseDnsProviderConfig(ABC):
    """Shared fields for every dns-lexicon provider."""

    domain: str
    """DNS zone (e.g. ``example.com``)."""

    propagation_delay: int = 30
    """Seconds to wait after TXT record creation before ACME verification."""

    ttl: int = 300
    """TTL applied to created records."""

    @abstractmethod
    def to_lexicon_dict(self) -> dict:
        """Return the ``provider_name`` + provider-specific options
        expected by :class:`lexicon.config.ConfigResolver`."""
        ...


@dataclass(frozen=True, slots=True)
class Rfc2136Config(_BaseDnsProviderConfig):
    """Configuration for RFC 2136 dynamic DNS updates.

    Uses the *ddns* dns-lexicon provider which speaks the RFC 2136
    protocol over TCP with TSIG authentication.

    Args:
        domain: DNS zone.
        server: IP address of the authoritative DNS server.
        tsig_key: TSIG key in ``<algorithm>:<key_id>:<secret>`` format
            (e.g. ``hmac-sha256:mykey:base64secret==``).
    """

    server: str = ""
    """IP address of the authoritative DNS server."""

    tsig_key: str = ""
    """TSIG key in ``<algorithm>:<key_id>:<secret>`` format."""

    def to_lexicon_dict(self) -> dict:
        return {
            "provider_name": "ddns",
            "domain": self.domain,
            "ttl": self.ttl,
            "ddns": {
                "ddns_server": self.server,
                "auth_token": self.tsig_key,
            },
        }


@dataclass(frozen=True, slots=True)
class GoogleDnsConfig(_BaseDnsProviderConfig):
    """Configuration for Google Cloud DNS.

    Uses the *googleclouddns* dns-lexicon provider.

    Args:
        domain: DNS zone.
        project_id: GCP project ID.
        service_account_info: Path to a GCP service-account JSON key file,
            **or** the JSON string itself.
    """

    project_id: str = ""
    service_account_info: str = ""

    def to_lexicon_dict(self) -> dict:
        return {
            "provider_name": "googleclouddns",
            "domain": self.domain,
            "ttl": self.ttl,
            "googleclouddns": {
                "auth_service_account_info": self.service_account_info,
                "auth_project": self.project_id,
            },
        }


@dataclass(frozen=True, slots=True)
class CloudflareConfig(_BaseDnsProviderConfig):
    """Configuration for Cloudflare DNS.

    Uses the *cloudflare* dns-lexicon provider.

    Args:
        domain: DNS zone.
        api_token: Cloudflare API token with ``Zone:DNS:Edit`` permission.
    """

    api_token: str = ""
    zone_id: str = ""

    def to_lexicon_dict(self) -> dict:
        provider: dict = {"auth_token": self.api_token}
        if self.zone_id:
            provider["zone_id"] = self.zone_id
        return {
            "provider_name": "cloudflare",
            "domain": self.domain,
            "ttl": self.ttl,
            "cloudflare": provider,
        }
