"""Tests for CLI (help, list-siem, list-pipelines, conversion with mock)."""

from io import StringIO
from unittest.mock import patch

import pytest

from sigmaforge.cli import get_parser, list_pipelines, list_siem, main, run_convert


def test_help_exits_zero():
    """--help prints usage and exits 0."""
    with patch("sys.argv", ["sigmaforage", "--help"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0


def test_version_exits_zero():
    """--version prints version and exits 0."""
    with patch("sys.argv", ["sigmaforage", "--version"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0


def test_list_siem_exits_zero():
    """--list-siem prints SIEMs and exits 0."""
    with patch("sys.argv", ["sigmaforage", "--list-siem"]):
        with patch("sys.stdout", new_callable=StringIO) as out:
            code = main()
        assert code == 0
        assert "splunk" in out.getvalue().lower()
        assert "elasticsearch" in out.getvalue().lower()


def test_list_pipelines_exits_zero():
    """--list-pipelines prints pipelines and exits 0."""
    with patch("sys.argv", ["sigmaforage", "--list-pipelines"]):
        with patch("sys.stdout", new_callable=StringIO) as out:
            code = main()
        assert code == 0
        assert "sysmon" in out.getvalue().lower()


def test_missing_input_returns_error():
    """No -i and no --interactive should error."""
    parser = get_parser()
    args = parser.parse_args(["-s", "splunk"])
    assert args.input is None
    with patch("sys.stderr", new_callable=StringIO):
        code = run_convert(args)
    assert code == 2


def test_missing_siem_returns_error():
    """No -s and not interactive should error."""
    parser = get_parser()
    args = parser.parse_args(["-i", "examples/sample_sigma_rule.yml"])
    assert args.siems is None
    with patch("sys.stderr", new_callable=StringIO):
        code = run_convert(args)
    assert code == 2


@patch("sigmaforge.cli.convert_sigma_to_siem")
def test_convert_success_prints_output(mock_convert):
    """When conversion succeeds, output is printed (or written to -o)."""
    mock_convert.return_value = (True, "index=main Image=*whoami*")
    parser = get_parser()
    args = parser.parse_args([
        "-i", "examples/sample_sigma_rule.yml",
        "-s", "splunk",
        "--no-header",
    ])
    with patch("sys.stdout", new_callable=StringIO) as out:
        code = run_convert(args)
    assert code == 0
    assert "whoami" in out.getvalue() or "Image" in out.getvalue()
    mock_convert.assert_called()


@patch("sigmaforge.cli.convert_sigma_to_siem")
def test_convert_writes_to_file_when_o_specified(mock_convert):
    """With -o FILE, output is written to file."""
    mock_convert.return_value = (True, "splunk query here")
    parser = get_parser()
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        outpath = f.name
    try:
        args = parser.parse_args([
            "-i", "examples/sample_sigma_rule.yml",
            "-s", "splunk",
            "--no-header",
            "-o", outpath,
        ])
        with patch("sys.stdout", new_callable=StringIO), patch("sys.stderr", new_callable=StringIO):
            code = run_convert(args)
        assert code == 0
        content = open(outpath).read()
        assert "splunk query" in content
    finally:
        import os
        os.unlink(outpath)
