"""Shared mTLS SSLContext builder for agent → smallhelp calls.

httpx's ``cert=(certfile, keyfile)`` parameter does NOT reliably present the
client certificate (observed: the server sees no client cert and returns 401,
while curl with the same files succeeds). Building an ssl.SSLContext ourselves
and loading the client cert into it via load_cert_chain works, so both the
config-pull and report clients use this.
"""

from __future__ import annotations

import os
import ssl


def _require(path: str, purpose: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"{purpose} not found: {path}")
    return path


def build_mtls_context(
    client_cert_path: str,
    client_key_path: str,
    ca_path: str | None = None,
) -> ssl.SSLContext:
    """Client SSLContext that presents the machine cert and verifies the server.

    ``ca_path`` is the smallstep root that verifies smallhelp's server cert;
    httpx does not use the OS trust store, so it must be supplied for a private
    CA. If omitted, the system default trust is used.
    """
    if ca_path:
        _require(ca_path, "smallstep root bundle (verifies smallhelp's TLS)")
        ctx = ssl.create_default_context(cafile=ca_path)
    else:
        ctx = ssl.create_default_context()
    _require(client_cert_path, "machine cert (mTLS client credential)")
    _require(client_key_path, "machine key (mTLS client credential)")
    ctx.load_cert_chain(client_cert_path, client_key_path)
    return ctx
