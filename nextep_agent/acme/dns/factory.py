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

    def _lexicon_config(self) -> ConfigResolver:
        """Create a :class:`ConfigResolver` for the configured DNS zone."""
        return ConfigResolver().with_dict(self._config.to_lexicon_dict())

    def _relative_name(self, name: str) -> str:
        """Strip the configured zone suffix from a fully-qualified record name.

        The record's zone is the one this handler is configured for
        (``self._config.domain``), NOT acmeow's per-SAN ``domain`` argument — a
        SAN like ``test.kvcc.dev`` lives in zone ``kvcc.dev``, so
        ``_acme-challenge.test.kvcc.dev`` must become ``_acme-challenge.test``.
        """
        zone = self._config.domain
        suffix = f".{zone}"
        if name.endswith(suffix):
            return name[: -len(suffix)]
        return name

    def _create_record(self, domain: str, name: str, value: str) -> None:
        # `domain` is acmeow's per-SAN base name; the actual zone is in config.
        relative = self._relative_name(name)
        cfg = self._lexicon_config()
        try:
            with Client(cfg) as ops:
                existing = ops.list_records("TXT", relative)
                for record in existing:
                    ops.delete_record(identifier=record["id"])
                ops.create_record("TXT", relative, value)
        except AuthenticationError as exc:
            raise DnsAuthError(f"Auth failed for zone {self._config.domain!r}: {exc}") from exc
        except LexiconError as exc:
            raise DnsRecordError(f"Failed to create TXT {name!r} in {self._config.domain!r}: {exc}") from exc
        logger.debug("Created TXT %s -> %s (zone: %s)", name, value, self._config.domain)

    def _delete_record(self, domain: str, name: str) -> None:
        relative = self._relative_name(name)
        cfg = self._lexicon_config()
        try:
            with Client(cfg) as ops:
                existing = ops.list_records("TXT", relative)
                for record in existing:
                    ops.delete_record(identifier=record["id"])
        except AuthenticationError as exc:
            raise DnsAuthError(f"Auth failed for zone {self._config.domain!r}: {exc}") from exc
        except LexiconError as exc:
            raise DnsRecordError(f"Failed to delete TXT {name!r} in {self._config.domain!r}: {exc}") from exc
        logger.debug("Deleted TXT %s (zone: %s)", name, self._config.domain)

    # -- public API -----------------------------------------------------------

    def build(self) -> CallbackDnsHandler:
        """Return a ready-to-use :class:`CallbackDnsHandler`."""
        return CallbackDnsHandler(
            self._create_record,
            self._delete_record,
            propagation_delay=self._config.propagation_delay,
        )
