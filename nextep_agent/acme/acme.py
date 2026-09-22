"""Short-lived ACME client session — thin wrapper over acmeow.

Ported from the WIP agent's ``acme/acme.py``, trimmed to just ``AcmeClient_``
(the per-issuance session). The app-level ``AcmeManager`` and the wizard-coupled
``AcmeEnrollment`` are gone — in nextep-agent the external flow runner
(:mod:`nextep_agent.flows.external_acme`) drives this directly.
"""

from __future__ import annotations

from logging import getLogger
from typing import cast

from acmeow import (
    AcmeClient,
    CallbackDnsHandler,
    ChallengeHandler,
    ChallengeType,
    DnsConfig,
    Identifier,
    KeyType,
    RetryConfig,
    RevocationReason,
)

from nextep_agent.acme.dns import DnsHandlerFactory
from nextep_agent.acme.dns.providers import _BaseDnsProviderConfig


class AcmeClient_:
    """Short-lived ACME client session for a single issuance operation."""

    def __init__(
        self,
        *,
        server_url: str,
        email: str,
        storage_path: str = "./acme_data",
        key_type: KeyType = KeyType.EC256,
        retry_config: RetryConfig | None = None,
        dns_config: DnsConfig | None = None,
        dns_provider: _BaseDnsProviderConfig | None = None,
        ca_bundle: str | None = None,
    ) -> None:
        self.logger = getLogger("acme")
        self._server_url = server_url
        self._email = email
        self._storage_path = str(storage_path)
        self._key_type = key_type
        self._retry_config = retry_config
        self._dns_config = dns_config
        self._ca_bundle = ca_bundle
        self._client: AcmeClient | None = None
        self._dns_factory: DnsHandlerFactory | None = (
            DnsHandlerFactory(dns_provider) if dns_provider else None
        )

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        self.logger.info("AcmeClient_ starting...")
        self._client = AcmeClient(
            server_url=self._server_url,
            email=self._email,
            storage_path=self._storage_path,
            retry_config=self._retry_config,
            # acmeow types verify_ssl as bool, but it flows straight through to
            # requests' Session.verify, which also accepts a CA-bundle path str.
            verify_ssl=cast(bool, self._ca_bundle if self._ca_bundle else True),
        )
        if self._dns_config:
            self._client.set_dns_config(self._dns_config)
        self._client.create_account()
        self.logger.info("AcmeClient_ ready (account: %s).", self._client.email)

    def stop(self) -> None:
        self.logger.info("AcmeClient_ stopping...")
        if self._client:
            self._client.close()
            self._client = None

    # -- public API ------------------------------------------------------------

    @property
    def client(self) -> AcmeClient:
        if self._client is None:
            raise RuntimeError("AcmeClient_ has not been started")
        return self._client

    @property
    def dns_handler(self) -> CallbackDnsHandler:
        if self._dns_factory is None:
            raise RuntimeError(
                "No dns_provider configured — pass a handler explicitly "
                "or set dns_provider"
            )
        return self._dns_factory.build()

    def _resolve_handler(
        self,
        handler: ChallengeHandler | None,
        challenge_type: ChallengeType,
    ) -> ChallengeHandler:
        if handler is not None:
            return handler
        if challenge_type != ChallengeType.DNS:
            raise ValueError(
                "An explicit handler is required for non-DNS challenge types"
            )
        return self.dns_handler

    def issue(
        self,
        domains: list[str],
        handler: ChallengeHandler | None = None,
        *,
        challenge_type: ChallengeType = ChallengeType.DNS,
        key_type: KeyType | None = None,
        preferred_chain: str | None = None,
        verify_dns: bool = True,
    ) -> tuple[str, str | None]:
        """Run the full ACME flow and return ``(cert_pem, key_pem)``.

        ``key_pem`` is ``None`` only when an external CSR was used at
        finalization; here acmeow generates the keypair, so it is present.
        """
        resolved = self._resolve_handler(handler, challenge_type)
        c = self.client
        identifiers = [Identifier.dns(d) for d in domains]

        self.logger.info("Creating order for %s", domains)
        c.create_order(identifiers)

        self.logger.info("Completing %s challenges", challenge_type.value)
        c.complete_challenges(
            resolved, challenge_type=challenge_type, verify_dns=verify_dns
        )

        kt = key_type or self._key_type
        self.logger.info("Finalizing order with %s key", kt.value)
        c.finalize_order(kt)

        cert_pem, key_pem = c.get_certificate(preferred_chain=preferred_chain)
        self.logger.info("Certificate issued for %s", domains)
        return cert_pem, key_pem

    def revoke(
        self,
        cert_pem: str | bytes,
        reason: RevocationReason | None = None,
    ) -> None:
        self.logger.info("Revoking certificate")
        self.client.revoke_certificate(cert_pem, reason=reason)
        self.logger.info("Certificate revoked")
