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

from nextep_agent import platform_paths


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
    def smallstep_root_pem(self) -> str:
        """The smallstep root cert as a PEM string. Verifies smallhelp's TLS
        (config pull/report) and step-ca's TLS (x5c sign). Baked into the org so
        no trust file need be provisioned per host; httpx does not use the OS
        trust store, so this is required for those private-CA surfaces."""

    @property
    def machine_cert_path(self) -> str:
        """AD machine cert certmonger keeps fresh — the mTLS + x5c credential.

        Defaults to the conventional certmonger output path for the node's OS
        family (Debian /etc/ssl, RHEL/OL /etc/pki/tls), detected at runtime so the
        agent reads whatever realmd/certmonger wrote without per-host config. A
        fork may override to force a non-standard location."""
        return platform_paths.machine_cert_path()

    @property
    def machine_key_path(self) -> str:
        """Key for :attr:`machine_cert_path`. OS-detected like it; override to
        force a non-standard location."""
        return platform_paths.machine_key_path()

    @property
    @abstractmethod
    def config_path(self) -> str:
        """Where the pulled AgentConfig is cached on disk (read back by
        ``status``)."""

    @property
    @abstractmethod
    def acme_admin_email(self) -> str:
        """Contact email for the external (ACME) flow's account registration."""
