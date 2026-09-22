"""RefreshService orchestration — with all I/O stubbed out.

Verifies the core loop: pull -> persist -> run each flow -> arm renewal ->
report, plus per-flow failure isolation.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import nextep_agent.refresh as refresh_mod
from nextep_agent.config.models import AgentConfig
from nextep_agent.flows.base import IssueResult


def _raw():
    return {
        "node_name": "host.example.com",
        "flows": [
            {
                "type": "internal",
                "cert_output_path": "/c0",
                "key_output_path": "/k0",
                "config": {"provisioner": "x5c", "hostname": "host"},
            },
            {
                "type": "external",
                "cert_output_path": "/c1",
                "key_output_path": "/k1",
                "config": {
                    "acme_provider": "letsencrypt",
                    "domains": ["host.example.com"],
                    "dns_provider": "cloudflare",
                    "dns_provider_config": {"domain": "example.com", "api_token": "t"},
                },
            },
        ],
    }


class _FakeScheduler:
    def __init__(self):
        self.scheduled = []

    def schedule_flow(self, job_id, run_at, func, *args):
        self.scheduled.append((job_id, run_at, args))


class _RecordingReporter:
    def __init__(self):
        self.events = []

    def report(self, **kw):
        self.events.append(kw)


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """A RefreshService with pull/persist/report/runner all stubbed."""
    cfg = AgentConfig.loads(json.dumps(_raw()))

    # stub config pull
    class _CC:
        def pull(self):
            return cfg

    monkeypatch.setattr(refresh_mod.RefreshService, "_config_client", lambda self: _CC())

    reporter = _RecordingReporter()
    monkeypatch.setattr(
        refresh_mod.RefreshService, "_report_client", lambda self: reporter
    )

    # persist to a temp path
    monkeypatch.setattr(refresh_mod, "config_path", lambda: str(tmp_path / "config.json"))

    sched = _FakeScheduler()
    svc = refresh_mod.RefreshService(
        spog_url="https://sh",
        machine_cert_path="/m.pem",
        machine_key_path="/m.key",
        smallstep_root_path=None,
        scheduler=sched,
    )
    return svc, cfg, sched, reporter, tmp_path


def _fake_make_runner(not_after=None, changed=True, fail_types=()):
    na = not_after or (datetime.now(timezone.utc) + timedelta(days=90))

    def factory(flow, org, defaults=None):
        class _R:
            def run(self):
                if str(flow.type) in fail_types:
                    raise RuntimeError("boom")
                return IssueResult(
                    flow_type=str(flow.type),
                    not_after=na,
                    sans=[flow.config.__dict__.get("hostname", "x")],
                    changed=changed,
                )

        return _R()

    return factory


def test_refresh_runs_all_flows_persists_and_reports(monkeypatch, wired):
    svc, cfg, sched, reporter, tmp_path = wired
    monkeypatch.setattr(refresh_mod, "make_runner", _fake_make_runner())

    result = svc.refresh()

    # config persisted
    assert (tmp_path / "config.json").exists()
    assert svc.config is result

    # both flows scheduled with a stable job id and a future run time
    assert len(sched.scheduled) == 2
    ids = {job_id for job_id, _, _ in sched.scheduled}
    assert ids == {"renew:internal:0", "renew:external:1"}
    for _job, run_at, _args in sched.scheduled:
        assert run_at > datetime.now(timezone.utc)

    # both flows reported with a next_scheduled_run
    assert len(reporter.events) == 2
    for ev in reporter.events:
        assert ev["status"] in ("issued", "renewed")
        assert ev["next_scheduled_run"] is not None
        assert ev["not_after"] is not None


def test_changed_flag_maps_to_status(monkeypatch, wired):
    svc, *_rest, reporter, _tp = wired
    monkeypatch.setattr(refresh_mod, "make_runner", _fake_make_runner(changed=False))
    svc.refresh()
    assert all(ev["status"] == "issued" for ev in reporter.events)


def test_per_flow_failure_is_isolated(monkeypatch, wired):
    svc, cfg, sched, reporter, _tp = wired
    monkeypatch.setattr(
        refresh_mod, "make_runner", _fake_make_runner(fail_types=("internal",))
    )
    svc.refresh()

    # the external flow still succeeded and got scheduled...
    assert [j for j, _, _ in sched.scheduled] == ["renew:external:1"]
    # ...and the internal flow reported a failure rather than crashing the run
    statuses = {ev["flow_type"]: ev["status"] for ev in reporter.events}
    assert statuses["internal"] == "failed"
    assert statuses["external"] in ("issued", "renewed")


def test_renew_one_targets_single_flow(monkeypatch, wired):
    svc, cfg, sched, reporter, _tp = wired
    monkeypatch.setattr(refresh_mod, "make_runner", _fake_make_runner())
    svc._config = cfg  # simulate a prior refresh
    svc.renew_one(1)
    assert len(reporter.events) == 1
    assert reporter.events[0]["flow_type"] == "external"
    assert sched.scheduled[0][0] == "renew:external:1"
