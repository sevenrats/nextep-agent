# nextep-agent

A small, pull-based, self-renewing certificate agent for smallhelp-managed
machines. On activation it **pulls its own configuration from smallhelp** and
deploys the certificate flows configured for that host, then keeps them renewed.

Two flow types:

- **internal** — the x5c flow: present the AD machine cert (`machine.pem`, kept
  fresh by certmonger) as an x5c credential to smallstep/step-ca and receive a
  **separate service cert** whose SANs are injected server-side (DB-driven).
- **external** — ACME with a **DNS-01** challenge (Cloudflare / Google; the
  provider registry is extensible).

## How it runs

The agent is a tiny FastAPI server:

- `POST /update` — HMAC-verified wake-up nudge from smallhelp → triggers a full
  config pull + flow (re)issue.
- `GET /status` — local status (config summary + per-flow next scheduled run).
- `GET /healthz` — liveness.

Renewal is driven by APScheduler: after each issuance the agent reads the new
cert's `not_after`, schedules the next renewal at ~2/3 of the lifetime, and
**reports the computed `next_scheduled_run` to smallhelp** (the agent — not the
SPOG — is the source of truth for renewal timing).

### CLI (local, in-process)

```
nextep-agent serve      # run the server (default)
nextep-agent status     # config + per-flow cert state + next renewal
nextep-agent refresh    # pull config and apply now
nextep-agent install    # install/enable the systemd service
```

### Bootstrap settings (env)

| Var | Meaning | Default |
|-----|---------|---------|
| `NEXTEP_SPOG_URL` | smallhelp base URL | — |
| `NEXTEP_MACHINE_CERT` | AD machine cert (mTLS client + x5c credential) | `/etc/ssl/certs/machine.pem` |
| `NEXTEP_MACHINE_KEY` | its private key | `/etc/ssl/private/machine.key` |
| `NEXTEP_SMALLSTEP_ROOT` | PEM to verify smallhelp/step-ca TLS | `/etc/nextep-agent/ca.pem` |
| `NEXTEP_NUDGE_SECRET` | shared HMAC secret == smallhelp `REMOTE_UPDATE_SECRET` | — |
| `NEXTEP_BIND_HOST` / `NEXTEP_BIND_PORT` | server bind | `0.0.0.0` / `9999` |

## Server contract (what smallhelp must provide)

These endpoints are **not yet implemented in smallhelp** — this is the interface
the agent codes against (see the plan for the scoped follow-up server work).

### `GET /agent/config` — mTLS, config pull

- Client presents `machine.pem` (AD leaf). smallhelp validates it against the
  **AD CS root** and reads the Subject **CN → `Host.common_name`** (same
  convention as `webhook/router.py:_x5c_common_name`).
- smallhelp presents a server cert chaining to the **smallstep root** (the agent
  verifies against `NEXTEP_SMALLSTEP_ROOT`).
- Returns this host's `SystemConfig` JSON (see below). `404` if host unknown.

### `POST /agent/report` — mTLS, renewal/issue event

Body:

```json
{
  "host": "host0.example.org",
  "flow_type": "internal",
  "status": "issued|renewed|failed",
  "not_after": "2026-12-16T18:02:55+00:00",
  "next_scheduled_run": "2026-10-16T00:00:00+00:00",
  "provider": "internal",
  "duration": 3,
  "error": null
}
```

Recorded for display; `next_scheduled_run` is agent-authoritative.

### Nudge: smallhelp → agent

smallhelp's `RemoteUpdateService` (`status/remote_update.py`) POSTs to the
agent's **`/update`** (change the target path from `/acme`) with
`X-Ts` / `X-Nonce` / `X-Sig` (HMAC-SHA256 of `v1|<ts>|<nonce>|<body>`,
base64url, shared `REMOTE_UPDATE_SECRET`).

### `SystemConfig` shape

```json
{
  "node_name": "host0.example.org",
  "org": {
    "spog_url": "https://smallhelp.example.com",
    "smallstep_root_pem": "-----BEGIN CERTIFICATE-----\n...",
    "acme_directory_url": "",
    "acme_admin_email": "certificates@example.com"
  },
  "flows": [
    {
      "type": "internal",
      "cert_output_path": "/etc/ssl/certs/service.pem",
      "key_output_path": "/etc/ssl/private/service.key",
      "post_renewal_script": "systemctl reload nginx",
      "config": {
        "ca_url": "https://ca.example.com:444",
        "provisioner": "x5c",
        "x5c_cert_path": "/etc/ssl/certs/machine.pem",
        "x5c_key_path": "/etc/ssl/private/machine.key",
        "root_bundle_path": "/etc/nextep-agent/ca.pem",
        "hostname": "host0"
      }
    },
    {
      "type": "external",
      "cert_output_path": "/etc/ssl/certs/ext.pem",
      "key_output_path": "/etc/ssl/private/ext.key",
      "post_renewal_script": null,
      "config": {
        "acme_provider": "letsencrypt",
        "domains": ["app.example.com", "*.app.example.com"],
        "dns_provider": "cloudflare",
        "dns_provider_config": {
          "domain": "example.com", "api_token": "…", "zone_id": "…",
          "propagation_delay": 30, "ttl": 300
        },
        "account_dir": "/var/lib/nextep-agent/acme/accounts"
      }
    }
  ]
}
```

Deserialisation is forward-compatible (unknown keys dropped) and discriminated
twice: `type` → flow body class, and (external only) `dns_provider` → provider
config class.

## Reuse note

Ported from `smallhelp/wip-smallhelp-agent`: the acmeow engine (`acme/acme.py`),
the dns-lexicon glue (`acme/dns/*`), the `DataClass` serde (`base/models.py`),
and the CA-trust helpers (`x509/ca.py`). The x5c flow is net-new, ported from
`smallhelp/x5c_test.py`. Dropped: the curses wizard, loopback-websocket
enrollment, the unused SQLAlchemy/alembic layer, and the SSH concern.
