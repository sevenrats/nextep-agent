from enum import StrEnum

from nextep_agent.acme.dns.providers import (
    CloudflareConfig,
    GoogleDnsConfig,
    Rfc2136Config,
    _BaseDnsProviderConfig,
)

LETSENCRYPT_URL = "https://acme-v02.api.letsencrypt.org/directory"



class DnsProvidersEnum(StrEnum):
    """Supported dns-lexicon provider identifiers."""

    RFC2136 = "ddns"
    GOOGLE_CLOUD_DNS = "googleclouddns"
    CLOUDFLARE = "cloudflare"


_PROVIDER_CONFIG_CLASSES: dict[DnsProvidersEnum, type[_BaseDnsProviderConfig]] = {
    DnsProvidersEnum.RFC2136: Rfc2136Config,
    DnsProvidersEnum.GOOGLE_CLOUD_DNS: GoogleDnsConfig,
    DnsProvidersEnum.CLOUDFLARE: CloudflareConfig,
}