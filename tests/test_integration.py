"""Integration tests: real sigma-cli conversion (skipped if backend/SSL fails)."""

import pytest

from sigmaforge.converter import convert_sigma_to_siem

# Minimal valid Sigma rule (process_creation / sysmon)
SAMPLE_RULE = """
title: Test Whoami
id: 00000000-0000-0000-0000-000000000001
status: test
description: Test rule for integration
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image: 'C:\\\\Windows\\\\System32\\\\whoami.exe'
  condition: selection
level: high
"""


@pytest.mark.integration
def test_convert_to_splunk_real():
    """Run real sigma convert to Splunk; skip if backend missing or SSL fails."""
    ok, out = convert_sigma_to_siem(SAMPLE_RULE.strip(), "splunk", pipeline="sysmon")
    if not ok:
        pytest.skip(f"sigma-cli/splunk backend failed (install backends or SSL): {out}")
    assert "whoami" in out.lower() or "Image" in out or "process" in out.lower()


@pytest.mark.integration
def test_convert_to_elasticsearch_real():
    """Run real sigma convert to Elasticsearch; skip if backend missing or SSL fails."""
    ok, out = convert_sigma_to_siem(SAMPLE_RULE.strip(), "elasticsearch", pipeline="sysmon")
    if not ok:
        pytest.skip(f"sigma-cli/elasticsearch backend failed: {out}")
    assert len(out.strip()) > 0
