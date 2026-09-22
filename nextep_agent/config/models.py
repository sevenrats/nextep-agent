"""Configuration DTOs for nextep-agent.

The envelope is one ``AgentConfig`` persisted as one JSON file
(``/etc/nextep-agent/config.json``). Compared with the WIP agent's model
(see smallhelp/agent-dto.md) this:

  * drops the ``ssh`` concern,
  * replaces the single ``acme`` section with a **list of flows**, each carrying
    a top-level ``type`` discriminator (internal x5c / external ACME),
  * adds per-flow output paths and an optional post-renewal shell script.

Serialisation reuses :class:`~nextep_agent.base.models.DataClass`. Deserialisation
is hand-rolled and discriminated:

    FlowType            -> {InternalX5cConfig | ExternalAcmeConfig}
    DnsProvidersEnum    -> {CloudflareConfig | GoogleDnsConfig | Rfc2136Config}   (external only)
"""

from __future__ import annotations

import socket
from dataclasses import asdict, dataclass, field, fields
from typing import Self

from nextep_agent.acme.dns.constant import (
    _PROVIDER_CONFIG_CLASSES,
    DnsProvidersEnum,
)
from nextep_agent.acme.dns.providers import _BaseDnsProviderConfig
from nextep_agent.base.models import DataClass
from nextep_agent.config.constant import AcmeProvider, FlowMethod, FlowType


# --------------------------------------------------------------------------- #
# org-level (shared across nodes)
# --------------------------------------------------------------------------- #
@dataclass
class AgentOrganizationConfig:
    """Org-level settings shared identically across every node."""

    spog_url: str = ""
    #: PEM of the smallstep root, used to verify smallhelp's server cert on the
    #: mTLS config pull and step-ca's TLS on the x5c POST.
    smallstep_root_pem: str = ""
    #: ACME directory of the internal (smallstep) ACME CA, if the external flow
    #: ever targets it instead of Let's Encrypt.
    acme_directory_url: str = ""
    acme_admin_email: str = ""


# --------------------------------------------------------------------------- #
# per-flow config (the two concrete flow bodies)
# --------------------------------------------------------------------------- #
@dataclass
class InternalX5cConfig:
    """Body of an ``internal`` (x5c -> smallstep) flow."""

    ca_url: str = ""
    provisioner: str = ""
    #: The AD machine cert + key certmonger keeps fresh; presented as the x5c
    #: credential. Defaults match the certmonger enrollment output paths.
    x5c_cert_path: str = "/etc/ssl/certs/machine.pem"
    x5c_key_path: str = "/etc/ssl/private/machine.key"
    #: PEM bundle to verify step-ca's TLS. Empty -> use system trust.
    root_bundle_path: str = ""
    #: Requested subject/hostname. SANs come from the server (enrichment); this
    #: is the CSR CN / token subject.
    hostname: str = ""


@dataclass
class ExternalAcmeConfig:
    """Body of an ``external`` (ACME DNS-01) flow."""

    acme_provider: AcmeProvider = AcmeProvider.LETSENCRYPT
    domains: list[str] = field(default_factory=list)
    dns_provider: DnsProvidersEnum | None = None
    dns_provider_config: _BaseDnsProviderConfig | None = None
    account_dir: str = "/var/lib/nextep-agent/acme/accounts"


# --------------------------------------------------------------------------- #
# flow envelope (common fields + discriminated body)
# --------------------------------------------------------------------------- #
@dataclass
class FlowConfig:
    """One certificate flow.

    ``type`` is the category (internal/external) and ``method`` the concrete
    mechanism (x5c/scep/dns-01). Together they select how the flow issues; the
    runner is chosen on ``(type, method)``.
    """

    type: FlowType
    method: FlowMethod
    #: Where the issued service cert / key are written (per-flow, configurable).
    cert_output_path: str
    key_output_path: str
    config: InternalX5cConfig | ExternalAcmeConfig
    #: Optional shell script run after this flow successfully (re)issues.
    post_renewal_script: str | None = None


# --------------------------------------------------------------------------- #
# top-level envelope
# --------------------------------------------------------------------------- #
@dataclass
class AgentConfig(DataClass):
    node_name: str = field(default_factory=socket.gethostname)
    org: AgentOrganizationConfig | None = None
    flows: list[FlowConfig] = field(default_factory=list)

    # -- discriminated deserialisation ------------------------------------- #
    @classmethod
    def _from_dict(cls, data: dict) -> Self:
        node_name = data.get("node_name") or socket.gethostname()

        org = None
        if isinstance(data.get("org"), dict):
            org = _construct(AgentOrganizationConfig, data["org"])

        flows = [
            _deserialize_flow(f)
            for f in data.get("flows", [])
            if isinstance(f, dict)
        ]
        return cls(node_name=node_name, org=org, flows=flows)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _construct(klass, raw: dict):
    """Filter *raw* to *klass*'s field names and construct shallowly."""
    valid = {f.name for f in fields(klass)}
    return klass(**{k: v for k, v in raw.items() if k in valid})


_FLOW_CONFIG_CLASSES = {
    FlowType.INTERNAL: InternalX5cConfig,
    FlowType.EXTERNAL: ExternalAcmeConfig,
}


#: Default method per category, applied when the server omits `method` (keeps
#: older payloads working: internal→x5c, external→dns-01).
_DEFAULT_METHOD = {
    FlowType.INTERNAL: FlowMethod.X5C,
    FlowType.EXTERNAL: FlowMethod.DNS_01,
}


def _deserialize_flow(raw: dict) -> FlowConfig:
    flow_type = FlowType(raw["type"])
    method = (
        FlowMethod(raw["method"]) if raw.get("method") else _DEFAULT_METHOD[flow_type]
    )
    body_raw = raw.get("config") or {}
    body_cls = _FLOW_CONFIG_CLASSES[flow_type]

    if flow_type is FlowType.EXTERNAL:
        body = _deserialize_external(body_raw)
    else:
        body = _construct(body_cls, body_raw)

    return FlowConfig(
        type=flow_type,
        method=method,
        cert_output_path=raw["cert_output_path"],
        key_output_path=raw["key_output_path"],
        config=body,
        post_renewal_script=raw.get("post_renewal_script"),
    )


def _deserialize_external(raw: dict) -> ExternalAcmeConfig:
    valid = {f.name for f in fields(ExternalAcmeConfig)}
    kwargs = {k: v for k, v in raw.items() if k in valid}

    if kwargs.get("acme_provider"):
        kwargs["acme_provider"] = AcmeProvider(kwargs["acme_provider"])

    provider = kwargs.get("dns_provider")
    if provider:
        provider = DnsProvidersEnum(provider)
        kwargs["dns_provider"] = provider
        pconf_raw = raw.get("dns_provider_config") or {}
        pconf_cls = _PROVIDER_CONFIG_CLASSES[provider]
        pvalid = {f.name for f in fields(pconf_cls)}
        kwargs["dns_provider_config"] = pconf_cls(
            **{k: v for k, v in pconf_raw.items() if k in pvalid}
        )

    return ExternalAcmeConfig(**kwargs)


# --------------------------------------------------------------------------- #
# persistence
# --------------------------------------------------------------------------- #
def config_path() -> str:
    import platform

    if platform.system() == "Windows":
        return r"C:\ProgramData\nextep-agent\config.json"
    return "/etc/nextep-agent/config.json"
