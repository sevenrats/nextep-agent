"""FlowRunner ABC + shared issuance plumbing.

Each concrete runner knows how to obtain a service certificate for one flow and
writes it to that flow's configured output paths. Shared here: writing the
cert/key with sane permissions, running the optional post-renewal script, and
extracting ``not_after`` (used by the scheduler to compute the next renewal).
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from logging import getLogger
from pathlib import Path

from cryptography import x509

from nextep_agent.config.models import FlowConfig


@dataclass
class IssueResult:
    """Outcome of a single flow issuance, reported upstream and to the scheduler."""

    flow_type: str
    not_after: datetime
    sans: list[str]
    changed: bool


@dataclass
class BootstrapDefaults:
    """Agent-side bootstrap values a flow falls back to when the pulled config
    leaves them empty.

    The server dictates per-flow issuance config (ca_url, provisioner, ...), but
    machine identity + trust are agent-local: the smallstep root that verifies
    step-ca's TLS and the AD machine cert/key used as the x5c credential. These
    come from :class:`nextep_agent.settings.Settings`. (Trust *installation* is a
    later feature; for now the human ensures these are present/flagged.)
    """

    smallstep_root_path: str | None = None
    machine_cert_path: str = ""
    machine_key_path: str = ""
    # Internal (x5c) flow constants used when the server serves them empty.
    ca_url: str = ""
    provisioner: str = ""
    # Output paths used when the server serves the flow's paths empty.
    cert_output_path: str = ""
    key_output_path: str = ""
    # External (ACME) flow: contact email for account registration.
    acme_admin_email: str = ""


class FlowRunner(ABC):
    """Base class for a single flow's issuance."""

    def __init__(
        self, flow: FlowConfig, defaults: "BootstrapDefaults | None" = None
    ) -> None:
        self.flow = flow
        self.defaults = defaults or BootstrapDefaults()
        self.logger = getLogger("flow")

    @abstractmethod
    def _obtain(self) -> tuple[str, str]:
        """Obtain the certificate. Return ``(cert_chain_pem, key_pem)``."""
        raise NotImplementedError

    # -- orchestration --------------------------------------------------------
    def run(self) -> IssueResult:
        """Obtain, persist, run post-renewal hook, and report metadata."""
        cert_pem, key_pem = self._obtain()
        changed = self._write(cert_pem, key_pem)
        leaf = _leaf_cert(cert_pem)
        if changed and self.flow.post_renewal_script:
            self._run_post_renewal()
        return IssueResult(
            flow_type=str(self.flow.type),
            not_after=leaf.not_valid_after_utc,
            sans=_sans_of(leaf),
            changed=changed,
        )

    # -- helpers --------------------------------------------------------------
    def _write(self, cert_pem: str, key_pem: str | None) -> bool:
        """Write cert (and key, if given) to the flow's paths. Return whether
        the cert content changed from what was already on disk."""
        cert_out = self.flow.cert_output_path or self.defaults.cert_output_path
        key_out = self.flow.key_output_path or self.defaults.key_output_path
        if not cert_out or (key_pem is not None and not key_out):
            raise RuntimeError(
                "flow has no cert/key output path (set them on the flow or in "
                "the org config)"
            )
        changed = _write_if_changed(Path(cert_out), cert_pem, mode=0o644)
        if key_pem is not None:
            _write_if_changed(Path(key_out), key_pem, mode=0o600)
        return changed

    def _run_post_renewal(self) -> None:
        script = self.flow.post_renewal_script
        assert script is not None
        self.logger.info("Running post-renewal script for %s flow", self.flow.type)
        try:
            result = subprocess.run(
                script, shell=True, capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                self.logger.error(
                    "post-renewal script exited %d: %s",
                    result.returncode,
                    result.stderr.strip(),
                )
            else:
                self.logger.info("post-renewal script ok")
        except subprocess.TimeoutExpired:
            self.logger.error("post-renewal script timed out")


# --------------------------------------------------------------------------- #
# module helpers
# --------------------------------------------------------------------------- #
def _write_if_changed(path: Path, content: str, *, mode: int) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_text() == content:
            return False
    except FileNotFoundError:
        pass
    path.write_text(content)
    path.chmod(mode)
    return True


def _leaf_cert(chain_pem: str) -> x509.Certificate:
    """The leaf is the first certificate in a PEM chain."""
    certs = x509.load_pem_x509_certificates(chain_pem.encode())
    if not certs:
        raise ValueError("no certificate found in issued PEM")
    return certs[0]


def _sans_of(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
