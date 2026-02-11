# Sigma Rules for Testing

This folder contains Sigma rules from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (rules-threat-hunting and rules) for use with SigmaForge.

## Structure

- **Windows/** – Windows process creation and related rules (~10)
- **Linux/** – Linux process creation rules (~10)
- **MacOS/** – macOS process creation rules (~10)
- **Cloud/** – Cloud (AWS, Okta, etc.) rules (~10)
- **Network/** – Network/DNS/Zeek rules (~10)
- **Proxy/** – Web proxy generic rules (~10)

## Populating rules

To download the full set from SigmaHQ (requires network and `certifi` for SSL):

```bash
python scripts/fetch_sigma_rules.py
```

Or install and run from the project root:

```bash
pip install certifi
python scripts/fetch_sigma_rules.py
```

## Using with SigmaForge

Specify the **path** to any rule file and the **SIEM** you want:

```bash
sigmaforge -i sigma-rules/Windows/proc_creation_win_curl_execution.yml -s splunk
sigmaforge -i sigma-rules/Windows/proc_creation_win_curl_execution.yml -s splunk -s elasticsearch -s azure-sentinel
```

Use an absolute path if you prefer:

```bash
sigmaforge -i /path/to/sigma-forge/sigma-rules/Windows/proc_creation_win_curl_execution.yml -s splunk
```
