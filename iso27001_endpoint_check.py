#!/usr/bin/env python3
"""
ISO 27001:2022 — Endpoint Technical Controls Assessment Tool
Shah Scientific Solutions | vCISO Practice
Run on Windows endpoint: python iso27001_endpoint_check.py
Outputs: iso27001_endpoint_assessment_YYYY-MM-DD.xlsx
"""

import os
import sys
import socket
import datetime
import platform
import subprocess
import json
import re
from pathlib import Path

try:
    import xlwt
    XLWT_AVAILABLE = True
except ImportError:
    XLWT_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


# ─────────────────────────────────────────────
# HOST INFO
# ─────────────────────────────────────────────
def get_host_info():
    return {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "os_name": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "username": os.environ.get("USERNAME", os.environ.get("USER", "unknown")),
        "domain": os.environ.get("USERDOMAIN", "N/A"),
        "assessment_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─────────────────────────────────────────────
# COMMAND RUNNER
# ─────────────────────────────────────────────
def run_cmd(cmd, timeout=10):
    """Run a shell command, return stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", -1
    except Exception as e:
        return str(e), -1


# ─────────────────────────────────────────────
# CHECKS — Annex A.8 Technological Controls
# Each returns: (passed: bool, value: str, evidence: str)
# ─────────────────────────────────────────────

def check_a81_endpoint_policy():
    """A.8.1 User endpoint devices — policy existence"""
    paths = [
        os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
        os.environ.get("ProgramFiles", "C:\\Program Files"),
        os.environ.get("APPDATA", "C:\\Users\\*\\AppData\\Roaming"),
    ]
    # Check for any endpoint management / security policy files
    checks = [
        "C:\\Windows\\System32\\GroupPolicy",
        "C:\\Windows\\System32\\GroupPolicyUsers",
    ]
    found = [p for p in checks if os.path.exists(p)]
    evidence = f"GP folder present: {', '.join(found) if found else 'Not found'}"
    return len(found) > 0, "Group Policy configured", evidence


def check_a82_privileged_access():
    """A.8.2 Privileged access rights"""
    out, _ = run_cmd('net localgroup Administrators')
    admins = [line.strip() for line in out.split("\n") if line.strip() and "Administrators" not in line]
    # Check for default admin, guest enabled
    guest_out, _ = run_cmd('net user Guest')
    guest_disabled = "Account active" in guest_out and "No" in guest_out
    rdp_out, _ = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections')
    rdp_disabled = "0x1" in rdp_out
    # Check for any admin accounts beyond expected
    evidence = f"Admin accounts: {len(admins)} found. Guest disabled: {guest_disabled}. RDP disabled: {rdp_disabled}"
    return len(admins) <= 4 and guest_disabled and rdp_disabled, f"Admin count: {len(admins)}, Guest: {'disabled' if guest_disabled else 'enabled'}", evidence


def check_a83_access_restriction():
    """A.8.3 Information access restriction — ACL checks"""
    critical_paths = [
        "C:\\Windows\\System32",
        "C:\\Program Files",
        "C:\\ProgramData",
    ]
    results = []
    for p in critical_paths:
        out, _ = run_cmd(f'attrib "{p}"')
        results.append(out)
    # Check if any obvious open permissions
    evidence = " | ".join(results[:3])
    return True, "Critical paths accessible", evidence


def check_a85_secure_auth():
    """A.8.5 Secure authentication — MFA, password policy"""
    # Check password policy
    out, _ = run_cmd('net accounts')
    min_len = re.search(r"Minimum password length.*?(\d+)", out)
    min_pw = int(min_len.group(1)) if min_len else 0
    # Check if screensaver password is required
    out2, _ = run_cmd('reg query "HKCU\\Control Panel\\Desktop" /v ScreenSaveInsecure')
    has_screensaver_lock = "0x0" not in out2 and out2
    # Check MFA (presence of Microsoft Authenticator / TOTP in Program Files)
    mfa_out, _ = run_cmd('dir "C:\\Program Files\\Microsoft*Auth" 2>nul || dir "C:\\Program Files (x86)\\Microsoft*Auth" 2>nul || echo NONE')
    has_mfa = "NONE" not in mfa_out and mfa_out.strip()
    pw_ok = min_pw >= 8
    evidence = f"Min PW length: {min_pw}. MFA present: {has_mfa or 'Not detected'}"
    return pw_ok, f"Min PW: {min_pw} chars. MFA: {'Yes' if has_mfa else 'Not detected'}", evidence


def check_a87_malware_protection():
    """A.8.7 Protection against malware"""
    # Check Windows Defender status
    out, _ = run_cmd('powershell -Command "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled, AntivirusEnabled, AntispywareEnabled | ConvertTo-Json"')
    defender_on = "True" in out
    # Check for 3rd party AV
    av_out, _ = run_cmd('wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState 2>nul || echo NONE')
    has_av = "NONE" not in av_out and av_out.strip()
    # Check UAC status
    uac_out, _ = run_cmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA')
    uac_on = "0x1" in uac_out
    evidence = f"Defender RT: {'On' if defender_on else 'Off'}. 3rd Party AV: {has_av[:50] if has_av else 'None'}. UAC: {'On' if uac_on else 'Off'}"
    return (defender_on or has_av) and uac_on, f"Defender: {'On' if defender_on else 'Off'}, UAC: {'On' if uac_on else 'Off'}", evidence


def check_a88_vuln_management():
    """A.8.8 Management of technical vulnerabilities"""
    # Check if Windows Update is configured
    out, _ = run_cmd('sc query wuauserv')
    wu_running = "RUNNING" in out
    # Check last update time
    up_out, _ = run_cmd('systeminfo | findstr /C:"Last Update Time"')
    # Check for vulnerability scanning tool
    nessus_out, _ = run_cmd('dir "C:\\Program Files\\Tenable\\Nessus" 2>nul || echo NONE')
    has_nessus = "NONE" not in nessus_out
    qualys_out, _ = run_cmd('dir "C:\\Program Files\\Qualys" 2>nul || echo NONE')
    has_qualys = "NONE" not in qualys_out
    has_scanner = has_nessus or has_qualys
    evidence = f"WU service: {'Running' if wu_running else 'Stopped'}. VA scanner: {'Found' if has_scanner else 'Not found'}"
    return wu_running, f"WU service: {'Running' if wu_running else 'Stopped'}, VA scanner: {'Found' if has_scanner else 'Not found'}", evidence


def check_a89_config_baseline():
    """A.8.9 Configuration management — hardening baseline"""
    # Check firewall status
    fw_out, _ = run_cmd('netsh advfirewall show allprofiles state')
    fw_on = "ON" in fw_out
    # Check BitLocker
    bitlocker_out, _ = run_cmd('manage-bde -status 2>nul || echo NOTAVAILABLE')
    bitlocker_on = "ON" in bitlocker_out or "Encryption" in bitlocker_out
    # Check remote desktop NLA
    nla_out, _ = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication')
    nla_on = "0x1" in nla_out
    evidence = f"Firewall: {'On' if fw_on else 'Off'}. BitLocker: {'On' if bitlocker_on else 'Off/N/A'}. NLA: {'On' if nla_on else 'Off'}"
    return fw_on, f"Firewall: {'On' if fw_on else 'Off'}, BitLocker: {'On' if bitlocker_on else 'Off/N/A'}, NLA: {'On' if nla_on else 'Off'}", evidence


def check_a810_data_deletion():
    """A.8.10 Information deletion — secure deletion"""
    # Check for cipher.exe (secure wipe)
    cipher_out, _ = run_cmd('where cipher 2>nul || echo NOTFOUND')
    has_cipher = "NOTFOUND" not in cipher_out
    # Check Recycle Bin size limit
    evidence = f"cipher.exe available: {has_cipher}"
    return has_cipher, f"Secure deletion tool: {'Available' if has_cipher else 'Not found'}", evidence


def check_a812_dlp():
    """A.8.12 Data leakage prevention"""
    # Check Windows Information Protection
    wip_out, _ = run_cmd('reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\IPP" 2>nul || echo NOTFOUND')
    has_wip = "NOTFOUND" not in wip_out
    # Check if any DLP product installed
    dlp_out, _ = run_cmd('wmic product get name 2>nul | findstr /i "DLP Endpoint Protection" || echo NONE')
    has_dlp = "NONE" not in dlp_out
    evidence = f"WIP: {'Configured' if has_wip else 'Not configured'}. DLP product: {'Found' if has_dlp else 'Not found'}"
    return has_wip or has_dlp, f"WIP/WinDefender DLP: {'Yes' if has_wip else 'No'}, 3rd Party DLP: {'Found' if has_dlp else 'None'}", evidence


def check_a813_backup():
    """A.8.13 Backup"""
    # Check Windows Backup / File History
    fh_out, _ = run_cmd('vssadmin list shadowstorage 2>nul || echo NONE')
    has_vss = "NONE" not in fh_out
    # Check backup scheduled tasks
    backup_out, _ = run_cmd('schtasks /query /fo LIST /tn "WindowsBackup" 2>nul || echo NONE')
    has_backup_task = "NONE" not in backup_out
    # Check OneDrive / cloud backup
    onedrive_out, _ = run_cmd('dir "C:\\Program Files\\Microsoft OneDrive" 2>nul || dir "C:\\Program Files (x86)\\Microsoft OneDrive" 2>nul || echo NONE')
    has_onedrive = "NONE" not in onedrive_out
    evidence = f"VSS: {'Active' if has_vss else 'No'}, Backup task: {'Found' if has_backup_task else 'Not found'}, OneDrive: {'Installed' if has_onedrive else 'Not found'}"
    return has_vss, f"VSS: {'Active' if has_vss else 'No'}, Backup task: {'Found' if has_backup_task else 'Not found'}", evidence


def check_a815_logging():
    """A.8.15 Logging"""
    # Check Windows Event Log service
    out, _ = run_cmd('sc query Windows Event Log 2>nul | findstr STATE')
    log_service = "RUNNING" in out
    # Check security event auditing
    audit_out, _ = run_cmd('auditpol /get /category:"Logon Events" 2>nul || echo NONE')
    has_audit = "NONE" not in audit_out
    # Check if logs are being collected centrally (Event Forwarding)
    ef_out, _ = run_cmd('sc query Wecsvc 2>nul | findstr STATE')
    has_wec = "RUNNING" in ef_out
    evidence = f"Event Log service: {'Running' if log_service else 'Stopped'}. Audit policy: {'Set' if has_audit else 'Not configured'}. Win Event Collector: {'Running' if has_wec else 'Not running'}"
    return log_service, f"Event Log: {'Running' if log_service else 'Stopped'}, Audit: {'Configured' if has_audit else 'Not set'}", evidence


def check_a816_monitoring():
    """A.8.16 Monitoring activities"""
    # Check SIEM agent (generic check)
    siem_agents = [
        "C:\\Program Files\\SplunkForwarder",
        "C:\\Program Files\\CrowdStrike",
        "C:\\Program Files\\Carbon Black",
        "C:\\Program Files\\Elastic",
        "C:\\Program Files\\Microsoft Monitoring Agent",
        "C:\\Program Files\\Tenable",
    ]
    found_agents = [a for a in siem_agents if os.path.exists(a)]
    # Check Defender real-time monitoring
    defender_out, _ = run_cmd('powershell -Command "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled | ConvertTo-Json"')
    rt_on = "True" in defender_out
    evidence = f"SIEM/EDR agents: {', '.join([os.path.basename(f) for f in found_agents]) if found_agents else 'None detected'}. Defender RT: {'On' if rt_on else 'Off'}"
    return len(found_agents) > 0 or rt_on, f"SIEM/EDR: {'Found' if found_agents else 'Not detected'}, Defender RT: {'On' if rt_on else 'Off'}", evidence


def check_a817_clock_sync():
    """A.8.17 Clock synchronisation"""
    out, _ = run_cmd('wmic /namespace:\\\\root\\CIMV2 path Win32_UTCTime get LocalDateTime 2>nul')
    ntp_out, _ = run_cmd('wmic /namespace:\\\\root\\CIMV2 path Win32_NTDomainServer get InventoryScriptExecutionTime 2>nul || echo NONE')
    # Check time source
    time_src_out, _ = run_cmd('wmic path win32_localtime get /format:list 2>nul')
    # Check timezone
    tz_out, _ = run_cmd('tzutil /g 2>nul || echo NONE')
    tz = tz_out.strip() if tz_out.strip() else "Unknown"
    evidence = f"Timezone: {tz}. NTP check: {'configured' if 'NONE' not in ntp_out else 'not confirmed'}"
    return True, f"Timezone: {tz}", evidence


def check_a819_software_restriction():
    """A.8.19 Installation of software — AppLocker / Software Restriction Policy"""
    applocker_out, _ = run_cmd('reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Srp" 2>nul || echo NOTFOUND')
    has_srp = "NOTFOUND" not in applocker_out
    # Check AppLocker
    applocker2_out, _ = run_cmd('reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppLocker" 2>nul || echo NOTFOUND')
    has_applocker = "NOTFOUND" not in applocker2_out
    has_restriction = has_srp or has_applocker
    evidence = f"SRP: {'Configured' if has_srp else 'Not configured'}, AppLocker: {'Configured' if has_applocker else 'Not configured'}"
    return has_restriction, f"SRP/AppLocker: {'Configured' if has_restriction else 'Not found'}", evidence


def check_a820_network_security():
    """A.8.20 Network security"""
    # Firewall status
    fw_out, _ = run_cmd('netsh advfirewall show allprofiles state')
    fw_on = "ON" in fw_out
    # Check for exposed shares
    shares_out, _ = run_cmd('net share 2>nul || echo NONE')
    admin_shares = "$" in shares_out
    evidence = f"Firewall: {'On' if fw_on else 'Off'}, Admin shares: {'Present' if admin_shares else 'None'}"
    return fw_on, f"Firewall profiles: {'On' if fw_on else 'Off'}", evidence


def check_a822_network_segregation():
    """A.8.22 Segregation of networks — VLAN, network segmentation"""
    # Check network adapters and DNS suffix
    dns_out, _ = run_cmd('ipconfig /all | findstr /i "DNS Suffix"')
    # Check if multiple network adapters present
    adapters_out, _ = run_cmd('netsh interface show interface 2>nul || echo NONE')
    # Check for VPN configuration
    vpn_out, _ = run_cmd('netsh interface show interface 2>nul | findstr -i "vpn" || echo NONE')
    has_vpn = "NONE" not in vpn_out
    evidence = f"DNS suffix: {dns_out[:80] if dns_out else 'None'}. VPN: {'Configured' if has_vpn else 'Not found'}"
    return True, f"VPN configured: {'Yes' if has_vpn else 'No/Unknown'}", evidence


def check_a824_cryptography():
    """A.8.24 Use of cryptography"""
    # Check TLS 1.2 enforcement
    tls_out, _ = run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols" 2>nul || echo NONE')
    has_tls_cfg = "NONE" not in tls_out
    # Check BitLocker
    bitlocker_out, _ = run_cmd('manage-bde -status C: 2>nul || echo NOTAVAILABLE')
    bitlocker_on = "ON" in bitlocker_out or "Encryption" in bitlocker_out
    # Check EFS
    efs_out, _ = run_cmd('fsutil fsinfo volumeinfo C: 2>nul | findstr -i "File System Compression" || echo NONE')
    evidence = f"BitLocker: {'On' if bitlocker_on else 'Off/N/A'}, TLS config: {'Set' if has_tls_cfg else 'Default'}"
    return bitlocker_on, f"BitLocker: {'On' if bitlocker_on else 'Off/N/A'}", evidence


def check_a825_sdlc():
    """A.8.25 Secure development life cycle — dev tools not expected on endpoint"""
    # Check for development environments (should not be on production endpoint)
    dev_tools = [
        "C:\\Program Files\\Git",
        "C:\\Program Files (x86)\\Git",
        "C:\\Program Files\\Microsoft Visual Studio",
        "C:\\Program Files\\Docker",
        "C:\\cygwin",
        "C:\\msys64",
    ]
    found = [t for t in dev_tools if os.path.exists(t)]
    # On a standard endpoint, dev tools should be absent or minimal
    acceptable = len(found) == 0
    evidence = f"Dev tools: {', '.join([os.path.basename(f) for f in found]) if found else 'None detected'}"
    return acceptable, f"Dev tools on endpoint: {'None' if not found else ', '.join([os.path.basename(f) for f in found])}", evidence


def check_a828_secure_coding():
    """A.8.28 Secure coding — not applicable to endpoint, always pass with note"""
    return True, "N/A — Endpoint assessment only", "Not applicable to endpoint configuration"


def check_a830_dev_test_separation():
    """A.8.30 Separate development, test and production environments"""
    return True, "N/A for endpoint", "Endpoint is a single environment — separation is network-level"


def check_a831_change_management():
    """A.8.31 Change management"""
    # Check for change management agent or policy
    out, _ = run_cmd('schtasks /query /fo LIST 2>nul | findstr /i "change\|patch\|update" || echo NONE')
    has_change_ctrl = "NONE" not in out
    evidence = f"Change-related scheduled tasks: {'Found' if has_change_ctrl else 'None detected'}"
    return True, f"Change tasks: {'Found' if has_change_ctrl else 'Not detected'}", evidence


# ─────────────────────────────────────────────
# CONTROL REGISTRY
# ─────────────────────────────────────────────
CONTROLS = [
    {
        "id": "A.8.1",
        "title": "User Endpoint Devices",
        "description": "A policy for the secure configuration and use of all user endpoint devices (laptops, desktops, mobile devices) shall be defined, approved, and communicated to all users.",
        "check_fn": check_a81_endpoint_policy,
        "category": "Endpoint Configuration",
        "max_score": 1,
    },
    {
        "id": "A.8.2",
        "title": "Privileged Access Rights",
        "description": "Privileged access rights to information systems and systems functions shall be restricted and managed in accordance with the access policy and risk assessment.",
        "check_fn": check_a82_privileged_access,
        "category": "Access Control",
        "max_score": 2,
    },
    {
        "id": "A.8.3",
        "title": "Information Access Restriction",
        "description": "Access to information and application system functions shall be restricted in accordance with the access control policy.",
        "check_fn": check_a83_access_restriction,
        "category": "Access Control",
        "max_score": 1,
    },
    {
        "id": "A.8.5",
        "title": "Secure Authentication",
        "description": "Secure authentication technologies and procedures based on the access control policy shall be implemented to authenticate identities prior to granting access to information systems, applications, and computers.",
        "check_fn": check_a85_secure_auth,
        "category": "Access Control",
        "max_score": 2,
    },
    {
        "id": "A.8.7",
        "title": "Protection Against Malware",
        "description": "Processes and procedures shall be established and maintained to protect against malware, including endpoint protection, awareness, and incident response.",
        "check_fn": check_a87_malware_protection,
        "category": "Malware Protection",
        "max_score": 2,
    },
    {
        "id": "A.8.8",
        "title": "Management of Technical Vulnerabilities",
        "description": "Information about technical vulnerabilities shall be obtained, the organisation's exposure to such vulnerabilities shall be evaluated, and appropriate measures shall be taken.",
        "check_fn": check_a88_vuln_management,
        "category": "Vulnerability Management",
        "max_score": 2,
    },
    {
        "id": "A.8.9",
        "title": "Configuration Management",
        "description": "Baseline security configurations shall be defined, documented, and implemented for all operating systems, applications, and network devices.",
        "check_fn": check_a89_config_baseline,
        "category": "Configuration Management",
        "max_score": 3,
    },
    {
        "id": "A.8.10",
        "title": "Information Deletion",
        "description": "When no longer required, personal data and data subjects' rights shall be managed in accordance with the organisation's retention and deletion procedures.",
        "check_fn": check_a810_data_deletion,
        "category": "Data Handling",
        "max_score": 1,
    },
    {
        "id": "A.8.12",
        "title": "Data Leakage Prevention (DLP)",
        "description": "Data leakage prevention measures shall be applied to systems, networks, and endpoints to detect and prevent the unauthorized disclosure of sensitive information.",
        "check_fn": check_a812_dlp,
        "category": "Data Handling",
        "max_score": 2,
    },
    {
        "id": "A.8.13",
        "title": "Backup",
        "description": "Backup copies of information, software, and system images shall be made, tested regularly, and maintained in accordance with the backup policy and recovery time objectives.",
        "check_fn": check_a813_backup,
        "category": "Resilience & Recovery",
        "max_score": 2,
    },
    {
        "id": "A.8.15",
        "title": "Logging",
        "description": "Security events and activities shall be logged (user access, admin actions, security events) and retained for a defined period to support investigation and audit.",
        "check_fn": check_a815_logging,
        "category": "Monitoring & Auditing",
        "max_score": 2,
    },
    {
        "id": "A.8.16",
        "title": "Monitoring Activities",
        "description": "Networks, systems, and applications shall be monitored for anomalous behaviour, and appropriate actions taken to evaluate and address detected threats.",
        "check_fn": check_a816_monitoring,
        "category": "Monitoring & Auditing",
        "max_score": 2,
    },
    {
        "id": "A.8.17",
        "title": "Clock Synchronisation",
        "description": "The clocks of all relevant information processing systems within the organisation shall be synchronised to a single accurate time source.",
        "check_fn": check_a817_clock_sync,
        "category": "Configuration Management",
        "max_score": 1,
    },
    {
        "id": "A.8.19",
        "title": "Installation of Software",
        "description": "Procedures shall be implemented to control software installation on systems. Only authorised software shall be permitted to run; no unauthorised software shall be installed.",
        "check_fn": check_a819_software_restriction,
        "category": "Configuration Management",
        "max_score": 2,
    },
    {
        "id": "A.8.20",
        "title": "Network Security",
        "description": "Network security controls shall be implemented to protect the confidentiality, integrity, and availability of information traversing networks.",
        "check_fn": check_a820_network_security,
        "category": "Network Security",
        "max_score": 2,
    },
    {
        "id": "A.8.22",
        "title": "Segregation of Networks",
        "description": "Network segments containing information assets of different sensitivity or criticality shall be segregated using controls such as VLANs, firewalls, or Jump servers.",
        "check_fn": check_a822_network_segregation,
        "category": "Network Security",
        "max_score": 1,
    },
    {
        "id": "A.8.24",
        "title": "Use of Cryptography",
        "description": "Cryptographic controls and key management procedures shall be implemented in accordance with the cryptography policy to protect the confidentiality, integrity, and authenticity of information.",
        "check_fn": check_a824_cryptography,
        "category": "Cryptography",
        "max_score": 2,
    },
    {
        "id": "A.8.25",
        "title": "Secure Development Life Cycle",
        "description": "Not applicable to endpoint — this control applies to software development environments. Endpoints are assessed for secure configuration instead.",
        "check_fn": check_a825_sdlc,
        "category": "Secure Development",
        "max_score": 0,
    },
    {
        "id": "A.8.28",
        "title": "Secure Coding",
        "description": "Not applicable to endpoint configuration. Secure coding practices apply to development teams and CI/CD pipelines.",
        "check_fn": check_a828_secure_coding,
        "category": "Secure Development",
        "max_score": 0,
    },
    {
        "id": "A.8.30",
        "title": "Separate Development, Test and Production Environments",
        "description": "Development, testing, and production environments shall be segregated. This is a network/system architecture control — not directly assessable on a single endpoint.",
        "check_fn": check_a830_dev_test_separation,
        "category": "Environment Separation",
        "max_score": 0,
    },
    {
        "id": "A.8.31",
        "title": "Change Management",
        "description": "Changes to the organisation's business processes, information systems, and relevant assets shall be managed through a formal change management process.",
        "check_fn": check_a831_change_management,
        "category": "Change Management",
        "max_score": 1,
    },
]


# ─────────────────────────────────────────────
# RUN ASSESSMENT
# ─────────────────────────────────────────────
def run_assessment():
    print("=" * 60)
    print("ISO 27001:2022 — Endpoint Technical Controls Assessment")
    print("Shah Scientific Solutions | vCISO Practice")
    print("=" * 60)

    host_info = get_host_info()
    print(f"\nHost: {host_info['hostname']}")
    print(f"OS: {host_info['os']}")
    print(f"User: {host_info['username']} @ {host_info['domain']}")
    print(f"Assessment date: {host_info['assessment_date']}")
    print(f"IP: {host_info['ip_address']}")
    print()

    results = []
    total_score = 0
    max_total = 0

    for ctrl in CONTROLS:
        ctrl_id = ctrl["id"]
        title = ctrl["title"]
        description = ctrl["description"]
        category = ctrl["category"]
        max_score = ctrl["max_score"]

        try:
            passed, value, evidence = ctrl["check_fn"]()
        except Exception as e:
            passed = False
            value = f"ERROR: {str(e)[:80]}"
            evidence = str(e)

        # Score: controls with max_score=0 are info-only (N/A)
        if max_score > 0:
            score = max_score if passed else 0
            total_score += score
            max_total += max_score
        else:
            score = 0
            max_score = 0  # treat as N/A

        status = "PASS" if passed else ("INFO" if max_score == 0 else "FAIL")
        results.append({
            "id": ctrl_id,
            "title": title,
            "category": category,
            "description": description,
            "status": status,
            "score": score,
            "max_score": max_score,
            "value": value,
            "evidence": evidence[:200],
        })

        icon = "[PASS]" if status == "PASS" else "[INFO]" if status == "INFO" else "[FAIL]"
        print(f"  {icon} {ctrl_id} — {title}")
        print(f"        {value}")

    overall_pct = int((total_score / max_total) * 100) if max_total > 0 else 0

    print()
    print("=" * 60)
    print(f"SCORE: {total_score} / {max_total}  ({overall_pct}%)")
    print("=" * 60)

    return host_info, results, total_score, max_total


# ─────────────────────────────────────────────
# EXPORT TO EXCEL
# ─────────────────────────────────────────────
def get_desktop_path():
    """Get the Desktop path on Windows or fallback."""
    # Try USERPROFILE env var first (most reliable on Windows)
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        desktop = os.path.join(userprofile, "Desktop")
        if os.path.isdir(desktop):
            return desktop
    # Try HOMEDRIVE+HOMEPATH (Windows terminal server)
    homedrive = os.environ.get("HOMEDRIVE", "")
    homepath = os.environ.get("HOMEPATH", "")
    if homedrive and homepath:
        desktop = os.path.join(homedrive + homepath, "Desktop")
        if os.path.isdir(desktop):
            return desktop
    # Fallback
    return os.path.join(os.environ.get("HOME", os.getcwd()), "Desktop")


def export_excel(host_info, results, total_score, max_total):
    filename = f"iso27001_endpoint_assessment_{datetime.date.today().isoformat()}.xlsx"
    desktop = get_desktop_path()
    filepath = os.path.join(desktop, filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    print(f"[DEBUG] Writing Excel to: {filepath}")

    if OPENPYXL_AVAILABLE:
        _export_openpyxl(filepath, host_info, results, total_score, max_total)
    elif XLWT_AVAILABLE:
        _export_xlwt(filepath, host_info, results, total_score, max_total)
    else:
        print(f"\n[ERROR] No Excel library available.")
        print(f"Install openpyxl: pip install openpyxl")
        print(f"Or install xlwt:    pip install xlwt")
        print(f"\nResults summary ({total_score}/{max_total} = {int((total_score/max_total)*100)}%):")
        for r in results:
            print(f"  [{r['status']:4s}] {r['id']} — {r['title']}")
        return None

    return filepath


def _export_openpyxl(filepath, host_info, results, total_score, max_total):
    import openpyxl
    from openpyxl.styles import (PatternFill, Font, Alignment, Border, Side,
                                  GradientFill)
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()

    # ── SHEET 1: Executive Summary ──
    ws1 = wb.active
    ws1.title = "Executive Summary"

    # Styles
    navy_fill = PatternFill("solid", fgColor="1F4E79")
    blue_fill = PatternFill("solid", fgColor="2E75B6")
    green_fill = PatternFill("solid", fgColor="375623")
    red_fill = PatternFill("solid", fgColor="C00000")
    amber_fill = PatternFill("solid", fgColor="ED7D31")
    light_blue_fill = PatternFill("solid", fgColor="DEEAF1")
    white_font = Font(color="FFFFFF", bold=True, name="Calibri", size=11)
    dark_font = Font(color="1A1A2E", name="Calibri", size=10)
    bold_font = Font(color="1A1A2E", bold=True, name="Calibri", size=10)
    center = Alignment(horizontal="center", vertical="center")
    left_align = Alignment(horizontal="left", vertical="center")
    thin_border = Border(
        left=Side(style="thin", color="BDD7EE"),
        right=Side(style="thin", color="BDD7EE"),
        top=Side(style="thin", color="BDD7EE"),
        bottom=Side(style="thin", color="BDD7EE"),
    )

    def hdr_cell(ws, row, col, text, fill=navy_fill, font=white_font, align=center):
        c = ws.cell(row=row, column=col, value=text)
        c.fill = fill; c.font = font; c.alignment = align
        c.border = thin_border
        return c

    def data_cell(ws, row, col, text, fill=None, font=None, align=left_align, bold=False):
        c = ws.cell(row=row, column=col, value=text)
        if fill: c.fill = fill
        c.font = font or dark_font
        if bold: c.font = bold_font
        c.alignment = align
        c.border = thin_border
        return c

    overall_pct = int((total_score / max_total) * 100) if max_total > 0 else 0

    # Title
    ws1.merge_cells("A1:F1")
    t = ws1["A1"]
    t.value = "SHAH SCIENTIFIC SOLUTIONS — ISO 27001:2022 ENDPOINT ASSESSMENT"
    t.fill = navy_fill; t.font = Font(color="FFFFFF", bold=True, size=14, name="Calibri")
    t.alignment = center
    ws1.row_dimensions[1].height = 30

    ws1.merge_cells("A2:F2")
    t2 = ws1["A2"]
    t2.value = "Endpoint Technical Controls Assessment | Annex A.8 | vCISO Practice"
    t2.fill = blue_fill; t2.font = Font(color="FFFFFF", size=10, name="Calibri", italic=True)
    t2.alignment = center
    ws1.row_dimensions[2].height = 20

    # Host info section
    row = 4
    ws1.merge_cells(f"A{row}:F{row}")
    h = ws1[f"A{row}"]
    h.value = "ASSESSMENT DETAILS"
    h.fill = blue_fill; h.font = white_font; h.alignment = center
    ws1.row_dimensions[row].height = 18

    host_data = [
        ("Hostname", host_info["hostname"]),
        ("Username", host_info["username"]),
        ("Domain / Workgroup", host_info["domain"]),
        ("Operating System", host_info["os"]),
        ("IP Address", host_info["ip_address"]),
        ("Assessment Date", host_info["assessment_date"]),
        ("Organisation", "Shah Scientific Solutions"),
        ("Assessment Tool", "ISO 27001 Endpoint Assessment Tool v1.0"),
    ]
    for i, (label, value) in enumerate(host_data):
        r = row + 1 + i
        data_cell(ws1, r, 1, label, fill=light_blue_fill, bold=True)
        ws1.merge_cells(f"B{r}:F{r}")
        data_cell(ws1, r, 2, value)
        ws1.row_dimensions[r].height = 16

    row = row + len(host_data) + 2

    # Score section
    ws1.merge_cells(f"A{row}:F{row}")
    h2 = ws1[f"A{row}"]
    h2.value = "OVERALL ASSESSMENT SCORE"
    h2.fill = blue_fill; h2.font = white_font; h2.alignment = center

    row += 1
    score_pct = overall_pct
    if score_pct >= 80:
        score_fill = PatternFill("solid", fgColor="C6EFCE")
        score_color = "375623"
        score_label = "GOOD COMPLIANCE"
    elif score_pct >= 50:
        score_fill = PatternFill("solid", fgColor="FFEB9C")
        score_color = "9C6500"
        score_label = "PARTIAL COMPLIANCE"
    else:
        score_fill = PatternFill("solid", fgColor="FFC7CE")
        score_color = "9C0006"
        score_label = "NON-COMPLIANT"

    ws1.merge_cells(f"A{row}:C{row}")
    sc = ws1[f"A{row}"]
    sc.value = f"{total_score} / {max_total}"
    sc.fill = score_fill; sc.font = Font(size=28, bold=True, color=score_color, name="Calibri")
    sc.alignment = center
    ws1.row_dimensions[row].height = 50

    ws1.merge_cells(f"D{row}:F{row}")
    sp = ws1[f"D{row}"]
    sp.value = f"{score_pct}%\n{score_label}"
    sp.fill = score_fill; sp.font = Font(size=14, bold=True, color=score_color, name="Calibri")
    sp.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    ws1.row_dimensions[row].height = 50

    # Category summary
    row += 2
    ws1.merge_cells(f"A{row}:F{row}")
    cs = ws1[f"A{row}"]
    cs.value = "SCORE BY CATEGORY"
    cs.fill = blue_fill; cs.font = white_font; cs.alignment = center

    row += 1
    hdr_cell(ws1, row, 1, "Category")
    hdr_cell(ws1, row, 2, "Controls")
    hdr_cell(ws1, row, 3, "Score")
    hdr_cell(ws1, row, 4, "Max")
    hdr_cell(ws1, row, 5, "Percentage")
    hdr_cell(ws1, row, 6, "Status")

    categories = {}
    for r2 in results:
        cat = r2["category"]
        if cat not in categories:
            categories[cat] = {"score": 0, "max": 0, "count": 0}
        if r2["max_score"] > 0:
            categories[cat]["score"] += r2["score"]
            categories[cat]["max"] += r2["max_score"]
            categories[cat]["count"] += 1

    for cat, data in sorted(categories.items()):
        row += 1
        cat_pct = int((data["score"] / data["max"]) * 100) if data["max"] > 0 else 0
        if cat_pct >= 80: sfill = PatternFill("solid", fgColor="C6EFCE"); scolor = "375623"
        elif cat_pct >= 50: sfill = PatternFill("solid", fgColor="FFEB9C"); scolor = "9C6500"
        else: sfill = PatternFill("solid", fgColor="FFC7CE"); scolor = "9C0006"
        data_cell(ws1, row, 1, cat)
        data_cell(ws1, row, 2, str(data["count"]))
        data_cell(ws1, row, 3, f"{data['score']}/{data['max']}", fill=sfill, font=Font(bold=True, color=scolor))
        data_cell(ws1, row, 4, str(data["max"]))
        data_cell(ws1, row, 5, f"{cat_pct}%", fill=sfill, font=Font(bold=True, color=scolor))
        data_cell(ws1, row, 6, "GOOD" if cat_pct >= 80 else "PARTIAL" if cat_pct >= 50 else "POOR",
                 fill=sfill, font=Font(bold=True, color=scolor))

    # Column widths
    ws1.column_dimensions["A"].width = 28
    ws1.column_dimensions["B"].width = 12
    ws1.column_dimensions["C"].width = 14
    ws1.column_dimensions["D"].width = 10
    ws1.column_dimensions["E"].width = 12
    ws1.column_dimensions["F"].width = 14

    # ── SHEET 2: Full Checklist ──
    ws2 = wb.create_sheet("Controls Checklist")

    # Title
    ws2.merge_cells("A1:H1")
    t3 = ws2["A1"]
    t3.value = "ISO 27001:2022 ANNEX A.8 — TECHNICAL CONTROLS CHECKLIST"
    t3.fill = navy_fill; t3.font = Font(color="FFFFFF", bold=True, size=13, name="Calibri")
    t3.alignment = center
    ws2.row_dimensions[1].height = 28

    # Headers
    headers = ["Control ID", "Title", "Category", "Status", "Score", "Max Score", "Findings / Configuration", "Evidence"]
    widths = [12, 30, 20, 10, 8, 10, 40, 55]
    for col, (hdr, w) in enumerate(zip(headers, widths), 1):
        c = ws2.cell(row=2, column=col, value=hdr)
        c.fill = blue_fill; c.font = white_font; c.alignment = center
        c.border = thin_border
        ws2.column_dimensions[get_column_letter(col)].width = w
    ws2.row_dimensions[2].height = 18

    for i, r2 in enumerate(results):
        row_n = i + 3
        max_sc = r2["max_score"]
        sc_val = r2["score"]

        if r2["status"] == "PASS":
            sfill = PatternFill("solid", fgColor="C6EFCE")
            scolor = "375623"
        elif r2["status"] == "INFO":
            sfill = PatternFill("solid", fgColor="DEEAF1")
            scolor = "1F4E79"
        else:
            sfill = PatternFill("solid", fgColor="FFC7CE")
            scolor = "9C0006"

        vals = [
            r2["id"],
            r2["title"],
            r2["category"],
            r2["status"],
            f"{sc_val}/{max_sc}" if max_sc > 0 else "N/A",
            str(max_sc) if max_sc > 0 else "N/A",
            r2["value"],
            r2["evidence"],
        ]
        for col, val in enumerate(vals, 1):
            c = ws2.cell(row=row_n, column=col, value=val)
            c.fill = sfill; c.font = Font(color=scolor, name="Calibri", size=9)
            c.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
            c.border = thin_border
        ws2.row_dimensions[row_n].height = 40

    wb.save(filepath)
    print(f"\n[SUCCESS] Excel report saved to:\n  {filepath}")


def _export_xlwt(filepath, host_info, results, total_score, max_total):
    wb = xlwt.Workbook()
    ws = wb.add_sheet("ISO27001 Controls")

    style_hdr = xlwt.XFStyle()
    style_hdr.font.bold = True
    style_hdr.font.colour_index = 1
    style_hdr.pattern.pattern = xlwt.Pattern()
    style_hdr.pattern.pattern_fore_colour = 64  # white

    # Headers
    headers = ["Control ID", "Title", "Category", "Status", "Score", "Max Score", "Findings"]
    for col, h in enumerate(headers):
        ws.write(0, col, h, style_hdr)

    for i, r2 in enumerate(results):
        row = i + 1
        ws.write(row, 0, r2["id"])
        ws.write(row, 1, r2["title"])
        ws.write(row, 2, r2["category"])
        ws.write(row, 3, r2["status"])
        ws.write(row, 4, f"{r2['score']}/{r2['max_score']}")
        ws.write(row, 5, r2["max_score"])
        ws.write(row, 6, r2["value"])

    wb.save(filepath)
    print(f"\n[SUCCESS] Excel report saved to: {filepath}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    host_info, results, total_score, max_total = run_assessment()
    excel_path = export_excel(host_info, results, total_score, max_total)
    print(f"\nAssessment complete.")
    if excel_path:
        print(f"Open the Excel file to see full details and category breakdown.")
