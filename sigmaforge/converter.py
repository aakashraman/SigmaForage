"""
Conversion engine: run sigma-cli to convert a Sigma rule to SIEM queries.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import certifi

from .siem_backends import SIEM_BACKENDS


def _subprocess_env() -> dict[str, str]:
    """Environment for sigma-cli subprocess so SSL uses certifi's CA bundle."""
    env = os.environ.copy()
    cert_path = certifi.where()
    env.setdefault("SSL_CERT_FILE", cert_path)
    env.setdefault("REQUESTS_CA_BUNDLE", cert_path)
    return env


def _sigma_cmd() -> list[str]:
    """Return the command prefix for sigma-cli (sigma or python -m sigma)."""
    sigma_exe = shutil.which("sigma")
    if sigma_exe:
        return [sigma_exe]
    return [sys.executable, "-m", "sigma"]


def convert_sigma_to_siem(
    sigma_content: str,
    siem_id: str,
    pipeline: str = "sysmon",
    rule_path: str | None = None,
) -> tuple[bool, str]:
    """
    Convert Sigma rule content to a SIEM query using sigma-cli.

    Args:
        sigma_content: Full YAML content of the Sigma rule.
        siem_id: SIEM identifier (e.g. 'splunk', 'elasticsearch').
        pipeline: Processing pipeline (e.g. 'sysmon', 'windows').
        rule_path: If provided, use this path for the rule file; otherwise use a temp file.

    Returns:
        (success: bool, output_or_error: str)
    """
    backend_id, _ = SIEM_BACKENDS.get(siem_id.lower(), (None, None))
    if not backend_id:
        return False, f"Unknown SIEM: {siem_id}. Use --list-siem to see supported platforms."

    use_temp = rule_path is None
    if use_temp:
        fd, rule_path = tempfile.mkstemp(suffix=".yml", prefix="sigma_")
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(sigma_content)
        except Exception as e:
            return False, f"Failed to write temp rule file: {e}"

    try:
        cmd = _sigma_cmd() + [
            "convert",
            "-t",
            backend_id,
            "-p",
            pipeline,
            rule_path,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env=_subprocess_env(),
        )
        out = result.stdout.strip() if result.stdout else ""
        err = result.stderr.strip() if result.stderr else ""

        if result.returncode != 0:
            msg = err or out or f"sigma convert exited with code {result.returncode}"
            if "Unknown target" in msg or "backend" in msg.lower():
                pkg = SIEM_BACKENDS.get(siem_id.lower(), (None, "pysigma-backend-..."))[1]
                msg += f"\n\nInstall the backend: sigma plugin install {backend_id}"
                msg += f"\nOr: pip install {pkg}"
            return False, msg
        return True, out or "(no output)"
    except FileNotFoundError:
        return False, (
            "sigma-cli not found. Install it with: pip install sigma-cli\n"
            "Then install backends: sigma plugin install splunk  (etc.)"
        )
    except subprocess.TimeoutExpired:
        return False, "Conversion timed out."
    except Exception as e:
        return False, str(e)
    finally:
        if use_temp and rule_path and Path(rule_path).exists():
            Path(rule_path).unlink(missing_ok=True)
