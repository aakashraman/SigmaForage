"""Tests for the conversion engine (with mocked sigma-cli)."""

from unittest.mock import MagicMock, patch

import pytest

from sigmaforge.converter import (
    _sigma_cmd,
    _subprocess_env,
    convert_sigma_to_siem,
)


def test_subprocess_env_includes_certifi():
    """SSL env should point to certifi bundle so sigma-cli can load MITRE ATT&CK over HTTPS."""
    env = _subprocess_env()
    assert "SSL_CERT_FILE" in env
    assert "REQUESTS_CA_BUNDLE" in env
    assert env["SSL_CERT_FILE"]
    assert env["REQUESTS_CA_BUNDLE"]


def test_sigma_cmd_returns_list():
    """_sigma_cmd returns a non-empty list (sigma or python -m sigma)."""
    cmd = _sigma_cmd()
    assert isinstance(cmd, list)
    assert len(cmd) >= 1


def test_unknown_siem_returns_false():
    """Unknown SIEM id returns (False, error message)."""
    ok, msg = convert_sigma_to_siem("title: x\ndetection:\n  x: 1\n  condition: x", "unknown-siem-xyz")
    assert ok is False
    assert "Unknown SIEM" in msg or "unknown" in msg.lower()


@patch("sigmaforge.converter.subprocess.run")
def test_successful_conversion(mock_run):
    """When sigma-cli succeeds, we return (True, stdout)."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="index=main Image=*whoami*",
        stderr="",
    )
    ok, out = convert_sigma_to_siem(
        "title: Whoami\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image: '*whoami*'\n  condition: selection",
        "splunk",
    )
    assert ok is True
    assert "whoami" in out or "Image" in out or out
    mock_run.assert_called_once()
    call_kw = mock_run.call_args[1]
    assert call_kw.get("env") is not None
    assert "SSL_CERT_FILE" in call_kw["env"]


@patch("sigmaforge.converter.subprocess.run")
def test_failed_conversion_returns_error(mock_run):
    """When sigma-cli fails, we return (False, error message)."""
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="Unknown target: splunk",
    )
    ok, msg = convert_sigma_to_siem(
        "title: X\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    x: 1\n  condition: selection",
        "splunk",
    )
    assert ok is False
    assert "splunk" in msg or "Install" in msg or "backend" in msg.lower()


@patch("sigmaforge.converter.subprocess.run")
def test_conversion_passes_correct_args(mock_run):
    """subprocess receives convert -t <backend> -p <pipeline> <rule_path>."""
    mock_run.return_value = MagicMock(returncode=0, stdout="query", stderr="")
    convert_sigma_to_siem(
        "title: X\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    x: 1\n  condition: selection",
        "elasticsearch",
        pipeline="windows",
    )
    args = mock_run.call_args[0][0]
    assert "convert" in args
    assert "-t" in args
    idx_t = args.index("-t")
    assert args[idx_t + 1] == "elasticsearch"
    assert "-p" in args
    idx_p = args.index("-p")
    assert args[idx_p + 1] == "windows"
