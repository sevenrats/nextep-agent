"""Org-level config contract.

Everything here is constant for an organization and identical across every one
of its nodes: where smallhelp lives, the smallstep CA + provisioner, the trust
bundle, and the machine credential paths certmonger maintains. These are NOT
per-host settings and are NOT sourced from env.

This open-source package ships only the *contract* — the abstract base. It has no
concrete org config and no default: an implementer subclasses
:class:`AbstractOrganizationConfig`, fills the properties, and passes an instance
to :func:`nextep_agent.agent.run`. See the kvcc-nextep-agent fork for the
canonical consumer shape.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class AbstractOrganizationConfig(ABC):
    """The org-level constants every node of an organization shares."""

    @property
    @abstractmethod
    def spog_url(self) -> str:
        """Base URL of the org's smallhelp (SPOG)."""

    @property
    @abstractmethod
    def ca_url(self) -> str:
        """step-ca base URL for the internal (x5c) flow."""

    @property
    @abstractmethod
    def provisioner(self) -> str:
        """step-ca provisioner name for the internal (x5c) flow."""

    @property
    @abstractmethod
    def smallstep_root_path(self) -> str:
        """PEM bundle verifying smallhelp's TLS (config pull) and step-ca's TLS
        (x5c sign). httpx does not use the OS trust store, so this is required."""

    @property
    @abstractmethod
    def machine_cert_path(self) -> str:
        """AD machine cert certmonger keeps fresh — the mTLS + x5c credential."""

    @property
    @abstractmethod
    def machine_key_path(self) -> str:
        """Key for :attr:`machine_cert_path`."""

    @property
    @abstractmethod
    def cert_output_path(self) -> str:
        """Fallback service-cert output path when a flow serves none."""

    @property
    @abstractmethod
    def key_output_path(self) -> str:
        """Fallback service-key output path when a flow serves none."""
