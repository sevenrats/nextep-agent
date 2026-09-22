"""Internal flow: x5c supplication to smallstep / step-ca.

Ported from smallhelp/x5c_test.py. Presents the AD machine cert (machine.pem,
kept fresh by certmonger) as the x5c credential, generates a fresh service
keypair + CSR, signs a one-time token whose ``x5c`` header carries the machine
chain, and POSTs ``{csr, ott}`` to ``/1.0/sign``. The issued service cert's SANs
are injected server-side by smallhelp's enrichment webhook (DB-driven), not by
the CSR.

Gotchas preserved from the reference:
  * token ``aud`` MUST be ``<scheme>://<host>/1.0/sign#x5c/<provisioner>``
    (fragment required; port stripped by step-ca).
  * token ``sans`` MUST equal the CSR SANs or step-ca returns 401/403.
"""

from __future__ import annotations

import base64
import datetime
import uuid

import httpx
import jwt  # PyJWT
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nextep_agent.config.models import InternalX5cConfig
from nextep_agent.flows.base import BootstrapDefaults, FlowRunner

_TOKEN_TTL = 300


def _alg_for_key(key) -> str:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        bits = key.curve.key_size
        return {256: "ES256", 384: "ES384", 521: "ES512"}.get(bits, "ES256")
    return "RS256"


class InternalX5cRunner(FlowRunner):
    def __init__(self, flow, defaults: BootstrapDefaults | None = None) -> None:
        super().__init__(flow, defaults)

    @property
    def _cfg(self) -> InternalX5cConfig:
        cfg = self.flow.config
        assert isinstance(cfg, InternalX5cConfig)
        return cfg

    def _obtain(self) -> tuple[str, str]:
        cfg = self._cfg
        hostname = cfg.hostname

        # ca_url + provisioner are internal-flow constants; the server may serve
        # them empty, so fall back to the org config.
        ca_url = cfg.ca_url or self.defaults.ca_url
        provisioner = cfg.provisioner or self.defaults.provisioner
        if not ca_url or not provisioner:
            raise RuntimeError(
                "internal flow needs a ca_url and provisioner (configure them on "
                "the flow or in the org config)"
            )

        # 1. Load the x5c credential (the AD machine cert/key) — the SAME
        # credential used for the mTLS config pull, supplied by the org config.
        # Fall back to the flow config's paths.
        cert_path = self.defaults.machine_cert_path or cfg.x5c_cert_path
        key_path = self.defaults.machine_key_path or cfg.x5c_key_path
        with open(cert_path, "rb") as f:
            chain = x509.load_pem_x509_certificates(f.read())  # leaf first
        with open(key_path, "rb") as f:
            x5c_key = serialization.load_pem_private_key(f.read(), password=None)
        alg = _alg_for_key(x5c_key)
        x5c_header = [
            base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
            for c in chain
        ]

        # 2. Fresh service key + CSR (CN + DNS SAN == hostname).
        new_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
            )
            .sign(new_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        # 3. Audience: scheme://host/1.0/sign#x5c/<provisioner> (fragment required).
        base = httpx.URL(ca_url)
        post_url = f"{ca_url.rstrip('/')}/1.0/sign"
        audience = f"{base.scheme}://{base.host}/1.0/sign#x5c/{provisioner}"

        # 4. One-time token, signed by the x5c key, chain in the x5c header.
        now = datetime.datetime.now(datetime.timezone.utc)
        token = jwt.encode(
            {
                "iss": provisioner,
                "sub": hostname,
                "aud": audience,
                "sans": [hostname],  # MUST match CSR SANs
                "iat": now,
                "nbf": now,
                "exp": now + datetime.timedelta(seconds=_TOKEN_TTL),
                "jti": uuid.uuid4().hex,
            },
            x5c_key,
            algorithm=alg,
            headers={"x5c": x5c_header},
        )

        # 5. POST to step-ca; verify its TLS against the smallstep root. This is
        # the SAME smallstep root the agent uses for the mTLS config pull,
        # threaded in via the org config. httpx does NOT use the OS trust
        # store, so verify=True (certifi) would reject step-ca's private cert —
        # a real root bundle path is required.
        root_bundle = cfg.root_bundle_path or self.defaults.smallstep_root_path
        if not root_bundle:
            raise RuntimeError(
                "no smallstep root bundle for step-ca TLS verify — set it in the "
                "org config (httpx does not use the OS trust store)"
            )
        with httpx.Client(verify=root_bundle, timeout=10.0) as client:
            resp = client.post(post_url, json={"csr": csr_pem, "ott": token})
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"step-ca returned {resp.status_code}: {resp.text.strip()}"
            )

        # 6. Parse issued cert + chain; pair with the generated key.
        data = resp.json()
        chain_pem = "".join(data.get("certChain") or [data["crt"]])
        key_pem = new_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        return chain_pem, key_pem
