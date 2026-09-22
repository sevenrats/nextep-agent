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

    def _obtain(self):
        return self._cert_pem, self._key_pem


def _flow(tmp_path, script=None) -> FlowConfig:
    return FlowConfig(
        type=FlowType.INTERNAL,
        method=FlowMethod.X5C,
        cert_output_path=str(tmp_path / "svc.pem"),
        key_output_path=str(tmp_path / "svc.key"),
        config=InternalX5cConfig(hostname="svc.example.com"),
        post_renewal_script=script,
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


def test_run_reports_unchanged_on_identical_reissue(tmp_path, self_signed):
    cert_pem, key_pem, _ = self_signed()
    flow = _flow(tmp_path)
    _FakeRunner(flow, cert_pem, key_pem).run()
    second = _FakeRunner(flow, cert_pem, key_pem).run()
    assert second.changed is False


def test_post_renewal_script_runs_on_change(tmp_path, self_signed):
    marker = tmp_path / "ran"
    cert_pem, key_pem, _ = self_signed()
    flow = _flow(tmp_path, script=f"touch {marker}")
    _FakeRunner(flow, cert_pem, key_pem).run()
    assert marker.exists()


def test_post_renewal_script_skipped_when_unchanged(tmp_path, self_signed):
    marker = tmp_path / "ran"
    cert_pem, key_pem, _ = self_signed()
    flow = _flow(tmp_path, script=f"touch {marker}")
    _FakeRunner(flow, cert_pem, key_pem).run()  # first: changed -> runs
    marker.unlink()
    _FakeRunner(flow, cert_pem, key_pem).run()  # second: unchanged -> skip
    assert not marker.exists()
