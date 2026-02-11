#!/usr/bin/env python3
"""
Fetch Sigma rules from SigmaHQ/sigma (rules-threat-hunting and rules) into sigma-rules/.
Usage: python scripts/fetch_sigma_rules.py
"""
import os
import ssl
import urllib.request
from pathlib import Path

try:
    import certifi
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CTX = ssl.create_default_context()

BASE = "https://raw.githubusercontent.com/SigmaHQ/sigma/master"
RULES_DIR = Path(__file__).resolve().parent.parent / "sigma-rules"

# (subpath on GitHub, local folder name)
RULES = {
    "Windows": [
        "rules-threat-hunting/windows/process_creation/proc_creation_win_curl_execution.yml",
        "rules-threat-hunting/windows/process_creation/proc_creation_win_7zip_password_extraction.yml",
        "rules-threat-hunting/windows/process_creation/proc_creation_win_attrib_system.yml",
        "rules-threat-hunting/windows/process_creation/proc_creation_win_boinc_execution.yml",
        "rules-threat-hunting/windows/process_creation/proc_creation_win_cmd_redirect.yml",
        "rules-threat-hunting/windows/process_creation/proc_creation_win_conhost_headless_execution.yml",
        "rules-threat-hunting/windows/process_creation/proc_creation_win_csc_compilation.yml",
        "rules-threat-hunting/windows/process_creation/proc_creation_win_curl_download.yml",
        "rules-threat-hunting/windows/process_creation/proc_creation_win_curl_useragent.yml",
        "rules-threat-hunting/windows/process_creation/proc_creation_win_findstr_password_recon.yml",
    ],
    "Linux": [
        "rules-threat-hunting/linux/process_creation/proc_creation_lnx_susp_process_termination_via_kill.yml",
        "rules-threat-hunting/linux/process_creation/proc_creation_lnx_susp_running_process_discovery.yml",
        "rules/linux/process_creation/proc_creation_lnx_apt_shell_execution.yml",
        "rules/linux/process_creation/proc_creation_lnx_at_command.yml",
        "rules/linux/process_creation/proc_creation_lnx_auditctl_clear_rules.yml",
        "rules/linux/process_creation/proc_creation_lnx_base64_decode.yml",
        "rules/linux/process_creation/proc_creation_lnx_base64_execution.yml",
        "rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml",
        "rules/linux/process_creation/proc_creation_lnx_clear_logs.yml",
        "rules/linux/process_creation/proc_creation_lnx_curl_usage.yml",
    ],
    "MacOS": [
        "rules-threat-hunting/macos/process_creation/proc_creation_macos_pbpaste_execution.yml",
        "rules/macos/process_creation/proc_creation_macos_applescript.yml",
        "rules/macos/process_creation/proc_creation_macos_base64_decode.yml",
        "rules/macos/process_creation/proc_creation_macos_clear_system_logs.yml",
        "rules/macos/process_creation/proc_creation_macos_clipboard_data_via_osascript.yml",
        "rules/macos/process_creation/proc_creation_macos_create_account.yml",
        "rules/macos/process_creation/proc_creation_macos_creds_from_keychain.yml",
        "rules/macos/process_creation/proc_creation_macos_csrutil_disable.yml",
        "rules/macos/process_creation/proc_creation_macos_file_and_directory_discovery.yml",
        "rules/macos/process_creation/proc_creation_macos_find_cred_in_files.yml",
    ],
    "Cloud": [
        "rules-threat-hunting/cloud/okta/okta_password_health_report_query.yml",
        "rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_success_without_mfa.yml",
        "rules/cloud/aws/cloudtrail/aws_cloudtrail_disable_logging.yml",
        "rules/cloud/aws/cloudtrail/aws_cloudtrail_guardduty_detector_deleted_or_updated.yml",
        "rules/cloud/aws/cloudtrail/aws_cloudtrail_imds_malicious_usage.yml",
        "rules/cloud/aws/cloudtrail/aws_cloudtrail_ssm_malicious_usage.yml",
        "rules/cloud/aws/cloudtrail/aws_cloudtrail_vpc_flow_logs_deleted.yml",
        "rules/cloud/aws/cloudtrail/aws_console_getsignintoken.yml",
        "rules/cloud/aws/cloudtrail/aws_delete_identity.yml",
        "rules/cloud/aws/cloudtrail/aws_ec2_import_key_pair_activity.yml",
    ],
    "Network": [
        "rules-threat-hunting/network/net_dns_low_reputation_etld.yml",
        "rules/network/dns/net_dns_external_service_interaction_domains.yml",
        "rules/network/dns/net_dns_mal_cobaltstrike.yml",
        "rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml",
        "rules/network/dns/net_dns_susp_b64_queries.yml",
        "rules/network/dns/net_dns_susp_telegram_api.yml",
        "rules/network/dns/net_dns_susp_txt_exec_strings.yml",
        "rules/network/dns/net_dns_wannacry_killswitch_domain.yml",
        "rules/network/zeek/zeek_dns_mining_pools.yml",
        "rules/network/zeek/zeek_http_executable_download_from_webdav.yml",
    ],
    "Proxy": [
        "rules-threat-hunting/web/proxy_generic/proxy_susp_class_extension_request.yml",
        "rules/web/proxy_generic/proxy_download_susp_dyndns.yml",
        "rules/web/proxy_generic/proxy_hello_world_user_agent.yml",
        "rules/web/proxy_generic/proxy_ua_empty.yml",
        "rules/web/proxy_generic/proxy_ua_powershell.yml",
        "rules/web/proxy_generic/proxy_telegram_api.yml",
        "rules/web/proxy_generic/proxy_raw_paste_service_access.yml",
        "rules/web/proxy_generic/proxy_susp_flash_download_loc.yml",
        "rules/web/proxy_generic/proxy_downloadcradle_webdav.yml",
        "rules/web/proxy_generic/proxy_pwndrop.yml",
    ],
}


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "SigmaForge/1.0"})
    with urllib.request.urlopen(req, timeout=30, context=SSL_CTX) as r:
        return r.read().decode("utf-8")


def main():
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    for folder, paths in RULES.items():
        out_dir = RULES_DIR / folder
        out_dir.mkdir(parents=True, exist_ok=True)
        for subpath in paths:
            name = os.path.basename(subpath)
            url = f"{BASE}/{subpath}"
            dest = out_dir / name
            try:
                content = fetch(url)
                dest.write_text(content, encoding="utf-8")
                print(f"OK {folder}/{name}")
            except Exception as e:
                print(f"SKIP {folder}/{name}: {e}")
    print("Done. Rules in", RULES_DIR)


if __name__ == "__main__":
    main()
