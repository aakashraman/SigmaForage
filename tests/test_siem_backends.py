"""Tests for SIEM backend mapping."""

import pytest

from sigmaforge.siem_backends import SIEM_BACKENDS, SIEM_DISPLAY_ORDER


def test_siem_backends_has_expected_platforms():
    """Key SIEMs should be present."""
    expected = {"splunk", "elasticsearch", "azure-sentinel", "ibm-qradar", "crowdstrike"}
    for key in expected:
        assert key in SIEM_BACKENDS, f"Missing SIEM: {key}"


def test_each_backend_has_id_and_package():
    """Each entry is (backend_id, pip_package)."""
    for name, value in SIEM_BACKENDS.items():
        assert isinstance(value, tuple), f"{name} should be (backend_id, package)"
        assert len(value) == 2, f"{name} should have 2 elements"
        backend_id, pkg = value
        assert backend_id, f"{name} backend_id must be non-empty"
        assert pkg, f"{name} package must be non-empty"


def test_display_order_subset_of_backends():
    """Every item in display order must be in SIEM_BACKENDS."""
    for key in SIEM_DISPLAY_ORDER:
        assert key in SIEM_BACKENDS, f"Display order has unknown SIEM: {key}"


def test_aliases_resolve():
    """Aliases (elk, microsoft-sentinel, etc.) map to same backend as canonical name."""
    assert SIEM_BACKENDS.get("elk") == SIEM_BACKENDS.get("elasticsearch")
    assert SIEM_BACKENDS.get("microsoft-sentinel") == SIEM_BACKENDS.get("azure-sentinel")
    assert SIEM_BACKENDS.get("helix") == SIEM_BACKENDS.get("trellix-helix")
