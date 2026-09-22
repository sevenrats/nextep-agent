"""Config DTO (de)serialisation — the two-discriminator polymorphic core."""

from __future__ import annotations

import json

import pytest

from nextep_agent.acme.dns.providers import CloudflareConfig, GoogleDnsConfig
from nextep_agent.config.constant import AcmeProvider, FlowType
from nextep_agent.config.models import (
    ExternalAcmeConfig,
    InternalX5cConfig,
    AgentConfig,
)


def _raw():
    return {
        "node_name": "host0.example.org",
        "org": {
            "spog_url": "https://smallhelp.example.com",
            "smallstep_root_pem": "---PEM---",
            "unknown_future_key": "ignored",  # forward-compat
        },
        "flows": [
            {
                "type": "internal",
                "cert_output_path": "/etc/ssl/certs/svc.pem",
                "key_output_path": "/etc/ssl/private/svc.key",
                "post_renewal_script": "systemctl reload nginx",
                "config": {
                    "ca_url": "https://ca.example.com:444",
                    "provisioner": "x5c",
                    "hostname": "host0",
                },
            },
            {
                "type": "external",
                "cert_output_path": "/etc/ssl/certs/ext.pem",
                "key_output_path": "/etc/ssl/private/ext.key",
                "config": {
                    "acme_provider": "letsencrypt",
                    "domains": ["ex.example.com", "*.ex.example.com"],
                    "dns_provider": "cloudflare",
                    "dns_provider_config": {
                        "domain": "example.com",
                        "api_token": "tok",
                        "zone_id": "zid",
                    },
                },
            },
        ],
    }


def test_envelope_fields():
    cfg = AgentConfig.loads(json.dumps(_raw()))
    assert cfg.node_name == "host0.example.org"
    assert cfg.org is not None
    assert cfg.org.spog_url == "https://smallhelp.example.com"
    assert len(cfg.flows) == 2


def test_forward_compat_drops_unknown_keys():
    # unknown_future_key on org must not raise and must be dropped.
    cfg = AgentConfig.loads(json.dumps(_raw()))
    assert not hasattr(cfg.org, "unknown_future_key")


def test_method_defaults_when_omitted():
    # Server may omit `method`; internal→x5c, external→dns-01 by default.
    from nextep_agent.config.constant import FlowMethod

    cfg = AgentConfig.loads(json.dumps(_raw()))
    assert cfg.flows[0].method is FlowMethod.X5C
    assert cfg.flows[1].method is FlowMethod.DNS_01


def test_explicit_method_parsed():
    from nextep_agent.config.constant import FlowMethod

    raw = _raw()
    raw["flows"][0]["method"] = "x5c"
    cfg = AgentConfig.loads(json.dumps(raw))
    assert cfg.flows[0].method is FlowMethod.X5C


def test_internal_flow_discriminator():
    cfg = AgentConfig.loads(json.dumps(_raw()))
    flow = cfg.flows[0]
    assert flow.type is FlowType.INTERNAL
    assert isinstance(flow.config, InternalX5cConfig)
    assert flow.config.provisioner == "x5c"
    assert flow.post_renewal_script == "systemctl reload nginx"
    # defaults fill in when omitted
    assert flow.config.x5c_cert_path == "/etc/ssl/certs/machine.pem"


def test_external_flow_two_level_discriminator():
    cfg = AgentConfig.loads(json.dumps(_raw()))
    flow = cfg.flows[1]
    assert flow.type is FlowType.EXTERNAL
    assert isinstance(flow.config, ExternalAcmeConfig)
    assert flow.config.acme_provider is AcmeProvider.LETSENCRYPT
    # second discriminator: dns_provider -> concrete frozen provider config
    assert isinstance(flow.config.dns_provider_config, CloudflareConfig)
    assert flow.config.dns_provider_config.api_token == "tok"
    assert flow.config.dns_provider_config.zone_id == "zid"
    # post_renewal_script omitted -> None
    assert flow.post_renewal_script is None


def test_google_provider_discriminator():
    raw = _raw()
    raw["flows"][1]["config"]["dns_provider"] = "googleclouddns"
    raw["flows"][1]["config"]["dns_provider_config"] = {
        "domain": "example.com",
        "project_id": "proj",
        "service_account_info": "{}",
    }
    cfg = AgentConfig.loads(json.dumps(raw))
    pconf = cfg.flows[1].config.dns_provider_config
    assert isinstance(pconf, GoogleDnsConfig)
    assert pconf.project_id == "proj"


def test_roundtrip_preserves_types():
    cfg = AgentConfig.loads(json.dumps(_raw()))
    again = AgentConfig.loads(cfg.dumps())
    assert isinstance(again.flows[0].config, InternalX5cConfig)
    assert isinstance(again.flows[1].config, ExternalAcmeConfig)
    assert isinstance(again.flows[1].config.dns_provider_config, CloudflareConfig)
    # value fidelity through a full dumps/loads cycle
    assert again.flows[1].config.dns_provider_config.to_lexicon_dict() == (
        cfg.flows[1].config.dns_provider_config.to_lexicon_dict()
    )


def test_empty_flows_and_no_org():
    cfg = AgentConfig.loads(json.dumps({"node_name": "h"}))
    assert cfg.node_name == "h"
    assert cfg.org is None
    assert cfg.flows == []


def test_zone_id_omitted_from_lexicon_when_empty():
    raw = _raw()
    raw["flows"][1]["config"]["dns_provider_config"].pop("zone_id")
    cfg = AgentConfig.loads(json.dumps(raw))
    lex = cfg.flows[1].config.dns_provider_config.to_lexicon_dict()
    assert "zone_id" not in lex["cloudflare"]


def test_unknown_flow_type_raises():
    raw = _raw()
    raw["flows"] = [
        {"type": "bogus", "cert_output_path": "/c", "key_output_path": "/k", "config": {}}
    ]
    with pytest.raises(ValueError):
        AgentConfig.loads(json.dumps(raw))
