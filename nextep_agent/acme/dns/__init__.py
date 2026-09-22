"""DNS provider configs + lexicon-backed handler factory.

``DnsHandlerFactory`` pulls in acmeow/dns-lexicon, so it is imported lazily via
``__getattr__``: modules that only need the provider configs / enum (e.g. the
config DTO layer) can import this package without those heavy deps present.
"""

from nextep_agent.acme.dns.constant import LETSENCRYPT_URL, DnsProvidersEnum
from nextep_agent.acme.dns.exception import DnsAuthError, DnsError, DnsRecordError
from nextep_agent.acme.dns.providers import (
    CloudflareConfig,
    GoogleDnsConfig,
    Rfc2136Config,
)

__all__ = [
    "CloudflareConfig",
    "DnsAuthError",
    "DnsError",
    "DnsHandlerFactory",
    "DnsProvidersEnum",
    "DnsRecordError",
    "GoogleDnsConfig",
    "LETSENCRYPT_URL",
    "Rfc2136Config",
]


def __getattr__(name: str):
    if name == "DnsHandlerFactory":
        from nextep_agent.acme.dns.factory import DnsHandlerFactory

        return DnsHandlerFactory
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
