"""Tests for sandbox target validation."""

import pytest

from vulnshield_common.scan_sandbox import (
    is_allowed_scan_target,
    sanitize_log_text,
)


def test_allow_localhost(monkeypatch):
    monkeypatch.setenv("SCAN_SANDBOX_MODE", "true")
    monkeypatch.setenv("ALLOW_EXTERNAL_TARGETS", "false")
    assert is_allowed_scan_target("http://localhost:8080")
    assert is_allowed_scan_target("127.0.0.1")


def test_allow_private_ip(monkeypatch):
    monkeypatch.setenv("SCAN_SANDBOX_MODE", "true")
    monkeypatch.setenv("ALLOW_EXTERNAL_TARGETS", "false")
    assert is_allowed_scan_target("192.168.1.10")


def test_reject_external(monkeypatch):
    monkeypatch.setenv("SCAN_SANDBOX_MODE", "true")
    monkeypatch.setenv("ALLOW_EXTERNAL_TARGETS", "false")
    assert not is_allowed_scan_target("https://example.com")


def test_allow_external_override(monkeypatch):
    monkeypatch.setenv("SCAN_SANDBOX_MODE", "true")
    monkeypatch.setenv("ALLOW_EXTERNAL_TARGETS", "true")
    assert is_allowed_scan_target("https://example.com")


def test_sanitize_truncates():
    result = sanitize_log_text("x" * 500, max_len=50)
    assert len(result) < 60
    assert "truncated" in result
