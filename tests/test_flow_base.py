"""FlowRunner orchestration + shared cert-handling helpers."""

from __future__ import annotations

import os
import stat

import pytest

from nextep_agent.config.constant import FlowMethod, FlowType
from nextep_agent.config.models import FlowConfig, InternalX5cConfig
from nextep_agent.flows.base import (
    FlowRunner,
    _leaf_cert,
    _sans_of,
    _write_if_changed,
)


class _FakeRunner(FlowRunner):
    """A runner whose _obtain returns fixed PEMs (no CA needed)."""

    def __init__(self, flow, cert_pem, key_pem):
        super().__init__(flow)
        self._cert_pem = cert_pem
        self._key_pem = key_pem
        self.obtain_calls = 0

    def _expected_sans(self):
        return set(self.flow.config.permitted_sans)

    def _obtain(self):
        self.obtain_calls += 1
        return self._cert_pem, self._key_pem


def _flow(tmp_path, script=None, sans=("svc.example.com",), renew_before_days=None,
          name="svc") -> FlowConfig:
    # cert/key land at <dir>/<name>.pem|.key -> tmp_path/svc.pem, tmp_path/svc.key
    return FlowConfig(
        type=FlowType.INTERNAL,
        method=FlowMethod.X5C,
        name=name,
        cert_output_dir=str(tmp_path),
        key_output_dir=str(tmp_path),
        config=InternalX5cConfig(
            hostname="svc.example.com", permitted_sans=list(sans)
        ),
        post_renewal_script=script,
        renew_before_days=renew_before_days,
    )


# -- helpers ---------------------------------------------------------------- #
def test_write_if_changed_creates_and_detects_change(tmp_path):
    p = tmp_path / "a" / "b.txt"
    assert _write_if_changed(p, "hello", mode=0o600) is True
    assert p.read_text() == "hello"
    # unchanged content -> False
    assert _write_if_changed(p, "hello", mode=0o600) is False
    # changed content -> True
    assert _write_if_changed(p, "world", mode=0o600) is True


def test_write_if_changed_sets_mode(tmp_path):
    p = tmp_path / "k.key"
    _write_if_changed(p, "secret", mode=0o600)
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600


def test_leaf_cert_and_sans(self_signed):
    cert_pem, _key, _na = self_signed(cn="a.example.com", sans=["a.example.com", "b.example.com"])
    leaf = _leaf_cert(cert_pem)
    assert _sans_of(leaf) == ["a.example.com", "b.example.com"]


def test_leaf_cert_empty_raises():
    with pytest.raises(ValueError):
        _leaf_cert("not a pem")


# -- orchestration ---------------------------------------------------------- #
def test_run_writes_outputs_and_reports_metadata(tmp_path, self_signed):
    cert_pem, key_pem, not_after = self_signed(sans=["svc.example.com"])
    flow = _flow(tmp_path)
    result = _FakeRunner(flow, cert_pem, key_pem).run()

    assert (tmp_path / "svc.pem").read_text() == cert_pem
    assert (tmp_path / "svc.key").read_text() == key_pem
    assert stat.S_IMODE(os.stat(tmp_path / "svc.key").st_mode) == 0o600
    assert result.flow_type == "internal"
    assert result.sans == ["svc.example.com"]
    # not_after compared at second granularity (PEM has no sub-second)
    assert abs((result.not_after - not_after).total_seconds()) < 2
    assert result.changed is True


def test_second_run_is_gated_and_skips_obtain(tmp_path, self_signed):
    # A current, SAN-matching cert with plenty of days left -> the gate skips
    # issuance entirely (does not even call _obtain).
    cert_pem, key_pem, _ = self_signed(sans=["svc.example.com"])
    flow = _flow(tmp_path, sans=["svc.example.com"])
    _FakeRunner(flow, cert_pem, key_pem).run()  # first issue
    second = _FakeRunner(flow, cert_pem, key_pem)
    result = second.run()
    assert result.changed is False
    assert second.obtain_calls == 0  # gate short-circuited before _obtain


def test_post_renewal_script_runs_on_change(tmp_path, self_signed):
    marker = tmp_path / "ran"
    cert_pem, key_pem, _ = self_signed(sans=["svc.example.com"])
    flow = _flow(tmp_path, script=f"touch {marker}", sans=["svc.example.com"])
    _FakeRunner(flow, cert_pem, key_pem).run()
    assert marker.exists()


def test_post_renewal_script_skipped_when_gated(tmp_path, self_signed):
    marker = tmp_path / "ran"
    cert_pem, key_pem, _ = self_signed(sans=["svc.example.com"])
    flow = _flow(tmp_path, script=f"touch {marker}", sans=["svc.example.com"])
    _FakeRunner(flow, cert_pem, key_pem).run()  # first: changed -> runs
    marker.unlink()
    _FakeRunner(flow, cert_pem, key_pem).run()  # second: gated -> skip
    assert not marker.exists()


# -- self-gating ------------------------------------------------------------ #
def test_gate_issues_when_no_cert_on_disk(tmp_path, self_signed):
    cert_pem, key_pem, _ = self_signed(sans=["svc.example.com"])
    runner = _FakeRunner(_flow(tmp_path, sans=["svc.example.com"]), cert_pem, key_pem)
    result = runner.run()
    assert runner.obtain_calls == 1
    assert result.changed is True


def test_gate_reissues_on_san_mismatch(tmp_path, self_signed):
    # On-disk cert has one SAN; config now wants an extra -> must reissue.
    cert_pem, key_pem, _ = self_signed(sans=["svc.example.com"])
    _FakeRunner(_flow(tmp_path, sans=["svc.example.com"]), cert_pem, key_pem).run()
    new_cert, new_key, _ = self_signed(sans=["svc.example.com", "extra.example.com"])
    runner = _FakeRunner(
        _flow(tmp_path, sans=["svc.example.com", "extra.example.com"]),
        new_cert,
        new_key,
    )
    runner.run()
    assert runner.obtain_calls == 1  # reissued because SANs changed


def test_gate_reissues_when_near_expiry(tmp_path, self_signed):
    # 10-day cert with default threshold min(30, 10//3=3)=3; 10 days left > 3 would
    # skip, so force renew_before_days high enough to trip it.
    cert_pem, key_pem, _ = self_signed(sans=["svc.example.com"], lifetime_days=10)
    _FakeRunner(_flow(tmp_path, sans=["svc.example.com"]), cert_pem, key_pem).run()
    runner = _FakeRunner(
        _flow(tmp_path, sans=["svc.example.com"], renew_before_days=15),
        cert_pem,
        key_pem,
    )
    runner.run()
    assert runner.obtain_calls == 1  # 10 days left <= 15 -> reissue


def test_gate_default_threshold_skips_long_lived(tmp_path, self_signed):
    # 90-day cert, no explicit threshold -> min(30, 30)=30; 90 left -> skip.
    cert_pem, key_pem, _ = self_signed(sans=["svc.example.com"], lifetime_days=90)
    _FakeRunner(_flow(tmp_path, sans=["svc.example.com"]), cert_pem, key_pem).run()
    runner = _FakeRunner(_flow(tmp_path, sans=["svc.example.com"]), cert_pem, key_pem)
    runner.run()
    assert runner.obtain_calls == 0
