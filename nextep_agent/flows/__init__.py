"""Flow runners + a factory dispatching on (type, method)."""

from __future__ import annotations

from nextep_agent.config.constant import FlowMethod, FlowType
from nextep_agent.config.models import FlowConfig, AgentOrganizationConfig
from nextep_agent.flows.base import BootstrapDefaults, FlowRunner, IssueResult


def make_runner(
    flow: FlowConfig,
    org: AgentOrganizationConfig | None,
    defaults: BootstrapDefaults | None = None,
) -> FlowRunner:
    """Select a runner for a flow based on its (type, method) pair.

    ``defaults`` supplies agent-side bootstrap fallbacks (smallstep root + machine
    cert/key) the internal flow uses when the pulled config leaves them empty.

    Built: internal/x5c, external/dns-01. Declared-but-unbuilt methods
    (internal/scep, other external challenges) raise a clear error until wired.
    """
    defaults = defaults or BootstrapDefaults()
    key = (flow.type, flow.method)

    if key == (FlowType.INTERNAL, FlowMethod.X5C):
        from nextep_agent.flows.internal_x5c import InternalX5cRunner

        return InternalX5cRunner(flow, defaults)

    if key == (FlowType.EXTERNAL, FlowMethod.DNS_01):
        from nextep_agent.flows.external_acme import ExternalAcmeRunner

        return ExternalAcmeRunner(flow, org, defaults)

    raise ValueError(
        f"no runner for flow type={flow.type} method={flow.method} "
        "(not yet implemented)"
    )


__all__ = ["BootstrapDefaults", "FlowRunner", "IssueResult", "make_runner"]
