"""Factory that builds ACMEOW ``CallbackDnsHandler`` instances from
dns-lexicon provider configurations."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from acmeow import CallbackDnsHandler
from lexicon.client import Client
from lexicon.config import ConfigResolver
from lexicon.exceptions import AuthenticationError, LexiconError

from nextep_agent.acme.dns.exception import DnsAuthError, DnsRecordError

if TYPE_CHECKING:
    from acme.dns.providers import _BaseDnsProviderConfig

logger = logging.getLogger(__name__)


class DnsHandlerFactory:
    """Build :class:`~acmeow.CallbackDnsHandler` instances backed by
    `dns-lexicon <https://github.com/dns-lexicon/dns-lexicon>`_.

    The factory is stateless – each call to :meth:`build` produces a
    self-contained handler that can be passed straight to
    :meth:`AcmeManager.issue` / :meth:`AcmeManager.renew`.

    Example::

        from acme.dns import DnsHandlerFactory, Rfc2136Config

        cfg = Rfc2136Config(
            domain="example.com",
            server="10.0.0.1",
            tsig_key="hmac-sha256:mykey:base64secret==",
        )
        factory = DnsHandlerFactory(cfg)
        handler = factory.build()
    """

    def __init__(self, config: _BaseDnsProviderConfig) -> None:
        self._config = config

    @property
    def config(self) -> _BaseDnsProviderConfig:
        return self._config

    # -- internal helpers -----------------------------------------------------

    def _lexicon_config(self, domain: str | None = None) -> ConfigResolver:
        """Create a :class:`ConfigResolver` for the given *domain*,
        falling back to the configured default zone."""
        base = self._config.to_lexicon_dict()
        if domain:
            base["domain"] = domain
        return ConfigResolver().with_dict(base)

    @staticmethod
    def _relative_name(name: str, domain: str) -> str:
        """Strip the zone suffix from a fully-qualified record name."""
        suffix = f".{domain}"
        if name.endswith(suffix):
            return name[: -len(suffix)]
        return name

    def _create_record(self, domain: str, name: str, value: str) -> None:
        relative = self._relative_name(name, domain)
        logger.info("_create_record: domain=%r name=%r relative=%r value=%r", domain, name, relative, value)
        cfg = self._lexicon_config(domain)
        try:
            with Client(cfg) as ops:
                existing = ops.list_records("TXT", relative)
                logger.info("_create_record: found %d existing records: %s", len(existing), existing)
                for record in existing:
                    ops.delete_record(identifier=record["id"])
                ops.create_record("TXT", relative, value)
        except AuthenticationError as exc:
            raise DnsAuthError(f"Auth failed for zone {domain!r}: {exc}") from exc
        except LexiconError as exc:
            raise DnsRecordError(f"Failed to create TXT {name!r} in {domain!r}: {exc}") from exc
        logger.debug("Created TXT %s -> %s (zone: %s)", name, value, domain)

    def _delete_record(self, domain: str, name: str) -> None:
        relative = self._relative_name(name, domain)
        cfg = self._lexicon_config(domain)
        try:
            with Client(cfg) as ops:
                existing = ops.list_records("TXT", relative)
                for record in existing:
                    ops.delete_record(identifier=record["id"])
        except AuthenticationError as exc:
            raise DnsAuthError(f"Auth failed for zone {domain!r}: {exc}") from exc
        except LexiconError as exc:
            raise DnsRecordError(f"Failed to delete TXT {name!r} in {domain!r}: {exc}") from exc
        logger.debug("Deleted TXT %s (zone: %s)", name, domain)

    # -- public API -----------------------------------------------------------

    def build(self) -> CallbackDnsHandler:
        """Return a ready-to-use :class:`CallbackDnsHandler`."""
        return CallbackDnsHandler(
            self._create_record,
            self._delete_record,
            propagation_delay=self._config.propagation_delay,
        )
