"""Flow factory dispatch."""

from __future__ import annotations

import pytest

from nextep_agent.config.constant import AcmeProvider, FlowMethod, FlowType
from nextep_agent.config.models import (
    ExternalAcmeConfig,
    FlowConfig,
    InternalX5cConfig,
    AgentOrganizationConfig,
)
from nextep_agent.flows import make_runner
from nextep_agent.flows.external_acme import ExternalAcmeRunner
from nextep_agent.flows.internal_x5c import InternalX5cRunner


def test_internal_x5c_dispatch():
    flow = FlowConfig(
        type=FlowType.INTERNAL,
        method=FlowMethod.X5C,
        cert_output_path="/c",
        key_output_path="/k",
        config=InternalX5cConfig(provisioner="x5c", hostname="h"),
    )
    assert isinstance(make_runner(flow, None), InternalX5cRunner)


def test_external_dns01_dispatch_passes_org():
    org = AgentOrganizationConfig(acme_admin_email="certificates@example.com")
    flow = FlowConfig(
        type=FlowType.EXTERNAL,
        method=FlowMethod.DNS_01,
        cert_output_path="/c",
        key_output_path="/k",
        config=ExternalAcmeConfig(acme_provider=AcmeProvider.LETSENCRYPT),
    )
    runner = make_runner(flow, org)
    assert isinstance(runner, ExternalAcmeRunner)
    assert runner.org is org


def test_unbuilt_method_raises():
    # internal/scep is declared but not yet implemented.
    flow = FlowConfig(
        type=FlowType.INTERNAL,
        method=FlowMethod.SCEP,
        cert_output_path="/c",
        key_output_path="/k",
        config=InternalX5cConfig(),
    )
    with pytest.raises(ValueError):
        make_runner(flow, None)
