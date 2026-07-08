"""Tests for sandbox scan target allowlisting."""

import pytest

from vulnshield_common.scan_sandbox import (
    is_allowed_scan_target,
    validate_target_or_raise,
)


@pytest.fixture(autouse=True)
def _sandbox_env(monkeypatch):
    monkeypatch.setenv("SCAN_SANDBOX_MODE", "true")
    monkeypatch.setenv("ALLOW_EXTERNAL_TARGETS", "false")
    monkeypatch.setenv("SANDBOX_ALLOW_PRIVATE", "false")


def test_localhost_allowed():
    assert is_allowed_scan_target("http://localhost:8080")
    assert is_allowed_scan_target("127.0.0.1")
    assert is_allowed_scan_target("::1")


def test_local_domain_allowed():
    assert is_allowed_scan_target("https://app.corp.local/login")


def test_docker_internal_allowed():
    assert is_allowed_scan_target("http://postgres:5432")
    assert is_allowed_scan_target("zap.vulnshield-net")


def test_external_blocked():
    assert not is_allowed_scan_target("https://example.com")
    assert not is_allowed_scan_target("8.8.8.8")


def test_rfc1918_when_private_enabled(monkeypatch):
    monkeypatch.setenv("SANDBOX_ALLOW_PRIVATE", "true")
    assert is_allowed_scan_target("10.0.0.5")
    assert is_allowed_scan_target("192.168.1.1")


def test_validate_raises_for_external():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        validate_target_or_raise("https://evil.example.com")
    assert exc.value.status_code == 403
