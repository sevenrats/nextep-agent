"""Enums for the nextep-agent config model.

Kept at the top of the import DAG (enums -> dataclasses -> registry), mirroring
the WIP agent's clean-DAG discipline so the polymorphic deserialisation in
:mod:`nextep_agent.config.models` has no import cycle.
"""

from enum import StrEnum


class FlowType(StrEnum):
    """Top-level flow category (first discriminator).

    ``INTERNAL`` == internally issued (x5c now; SCEP later).
    ``EXTERNAL`` == ACME (DNS-01 now; other challenges later).

    The concrete mechanism within a category is :class:`FlowMethod`.
    """

    INTERNAL = "internal"
    EXTERNAL = "external"


class FlowMethod(StrEnum):
    """Per-flow method (second discriminator), scoped by :class:`FlowType`.

    internal: ``X5C`` (built) | ``SCEP`` (future).
    external: ``DNS_01`` (built) | future challenge types.
    """

    # internal methods
    X5C = "x5c"
    SCEP = "scep"
    # external methods
    DNS_01 = "dns-01"


class AcmeProvider(StrEnum):
    """Which ACME CA the external flow targets."""

    LETSENCRYPT = "letsencrypt"
    LETSENCRYPT_STAGING = "letsencrypt-staging"
    INTERNAL_ACME = "internal-acme"
