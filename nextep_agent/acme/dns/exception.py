class DnsError(Exception):
    """Base exception for DNS provider operations."""


class DnsAuthError(DnsError):
    """Raised when the provider rejects credentials or the zone is not found."""


class DnsRecordError(DnsError):
    """Raised when a record operation fails (create conflict, delete not found, etc.)."""
