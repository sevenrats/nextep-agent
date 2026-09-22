"""External flow: ACME with a DNS-01 challenge (Cloudflare/Google/...).

Thin adapter over the ported :class:`~nextep_agent.acme.acme.AcmeClient_` and the
dns-lexicon provider glue. Writes the issued cert/key to the flow's configured
output paths (not the WIP agent's hardcoded ``default.{crt,key}``).
"""

from __future__ import annotations

from nextep_agent.acme.acme import AcmeClient_
from nextep_agent.acme.dns.constant import LETSENCRYPT_URL
from nextep_agent.config.constant import AcmeProvider
from nextep_agent.config.models import ExternalAcmeConfig
from nextep_agent.flows.base import FlowRunner


class ExternalAcmeRunner(FlowRunner):
    def __init__(self, flow, org) -> None:
        super().__init__(flow)
        self.org = org  # AgentOrganizationConfig | None (for internal-ACME dir/email)

    @property
    def _cfg(self) -> ExternalAcmeConfig:
        cfg = self.flow.config
        assert isinstance(cfg, ExternalAcmeConfig)
        return cfg

    def _obtain(self) -> tuple[str, str]:
        cfg = self._cfg
        if cfg.dns_provider_config is None:
            raise ValueError("external flow requires a dns_provider_config")

        # Directory URL + email + TLS-verify bundle depend on the ACME CA.
        if cfg.acme_provider is AcmeProvider.INTERNAL_ACME:
            if self.org is None or not self.org.acme_directory_url:
                raise ValueError(
                    "internal-acme requires org.acme_directory_url"
                )
            directory_url = self.org.acme_directory_url
            email = self.org.acme_admin_email
            ca_bundle = self.org.smallstep_root_pem or None
        else:
            directory_url = LETSENCRYPT_URL
            email = (self.org.acme_admin_email if self.org else "") or ""
            ca_bundle = None

        client = AcmeClient_(
            server_url=directory_url,
            email=email,
            storage_path=cfg.account_dir,
            dns_provider=cfg.dns_provider_config,
            ca_bundle=ca_bundle,
        )
        client.start()
        try:
            cert_pem, key_pem = client.issue(cfg.domains)
        finally:
            client.stop()

        if key_pem is None:
            raise RuntimeError("ACME returned no private key")
        return cert_pem, key_pem
