#!/usr/bin/env python3
"""
lab_hardening.py — Windows Hardening Toolkit
=============================================================================
Author  : Johnbosco (Chizitem) Ibeneme
Purpose : Windows security hardening operations for the OSSEC HIDS lab.
          These are the compliance/detection-substrate configurations that
          ensure Windows generates the Security Event Log entries that OSSEC
          and other SIEMs rely on for detection. Covers audit policy
          configuration, TLS/cipher suite hardening, protocol disabling, and
          guest account access control.

Scope   : Windows 11 / Windows Server security baselines. All operations are
          defensive hardening tasks aligned with CIS benchmarks, NIST SP
          800-52r2, and PCI-DSS requirements:
            - Audit policy (Event ID 4720, 4624, 4732, 7040 for detection)
            - TLS/SSL protocol hardening (disable deprecated, vulnerable protocols)
            - Cipher suite ordering (enforce AEAD + ECDHE/DHE)
            - Guest account access control (prevent privilege escalation)

Platform: WINDOWS ONLY — all commands use Windows auditpol and SCHANNEL registry.
          Requires Administrator privileges. Not portable to Linux/macOS.

Design  : Every hardening procedure is a subcommand with toggle variables
          where applicable. Hardening ($True/enable) is the default and
          recommended configuration. Lab simulation toggles ($False/disable)
          allow creation of deliberately vulnerable configs for testing
          vulnerability scanners or compliance assessment tools.

Usage   : python3 lab_hardening.py --help
          python3 lab_hardening.py audit-enable
          python3 lab_hardening.py protocols --secure
          python3 lab_hardening.py cipher-suites --insecure --dry-run

Requires: Python 3.8+, Windows 11/Server, Administrator privileges,
          PowerShell 5.1+ for SCHANNEL registry operations.
=============================================================================
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass


# =============================================================================
# CORE HELPER
# =============================================================================

@dataclass
class RunResult:
    command: str
    returncode: int
    stdout: str
    stderr: str


def run(command: str, *, dry_run: bool = False, check: bool = False,
        capture: bool = False) -> RunResult:
    """Execute a Windows command (auditpol, reg add, PowerShell) with dry-run support.

    Windows hardening commands are run directly as CMD/PowerShell invocations.
    Under --dry-run, the command is printed but not executed.
    """
    prefix = "[DRY-RUN] " if dry_run else "[RUN] "
    print(f"{prefix}{command}")

    if dry_run:
        return RunResult(command, 0, "", "")

    proc = subprocess.run(
        command, shell=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    result = RunResult(command, proc.returncode,
                       proc.stdout or "", proc.stderr or "")
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {command}")
    return result


def run_all(commands: list[str], *, dry_run: bool = False) -> None:
    """Run a sequence of Windows commands, stopping on first failure."""
    for cmd in commands:
        result = run(cmd, dry_run=dry_run)
        if not dry_run and result.returncode != 0:
            print(f"  ! stopped: previous command exited {result.returncode}",
                  file=sys.stderr)
            break


# =============================================================================
# AUDIT POLICY CONFIGURATION  (from Configure-AuditPolicy.ps1)
# =============================================================================
# The OSSEC HIDS lab failed to detect a user account creation (net user hacked /add)
# because Windows 11's default audit policy does not log Account Management events.
# Enabling auditpol categories 4720 (user created), 4732 (group membership changed),
# and 7040 (service startup mode changed) is what made OSSEC detections possible.

def audit_enable(dry_run: bool = False) -> None:
    """Enable all critical Windows audit policy categories for OSSEC detection.

    Enables:
      - Account Management   (Event 4720 user created, 4732 group changed)
      - Logon/Logoff         (Event 4624 login, 4625 failed login)
      - Policy Change        (audit config tampering detection)
      - Privilege Use        (sensitive operation tracking)
      - System               (Event 7040 service startup mode changed)

    Without these enabled, Windows will not generate the Security Event Log
    entries that OSSEC depends on for detection.
    """
    categories = [
        "Account Management",
        "Logon/Logoff",
        "Policy Change",
        "Privilege Use",
        "System",
    ]
    commands = [
        f'auditpol /set /category:"{cat}" /success:enable /failure:enable'
        for cat in categories
    ]
    commands.append("auditpol /get /category:*")  # verify
    run_all(commands, dry_run=dry_run)


def audit_disable(dry_run: bool = False) -> None:
    """Disable all audit policy categories (reverse the hardening).

    Use only in isolated test environments. This turns off all Security Event
    Log generation, breaking SIEM detection entirely.
    """
    categories = [
        "Account Management",
        "Logon/Logoff",
        "Policy Change",
        "Privilege Use",
        "System",
    ]
    commands = [
        f'auditpol /set /category:"{cat}" /success:disable /failure:disable'
        for cat in categories
    ]
    run_all(commands, dry_run=dry_run)


# =============================================================================
# TLS / SSL PROTOCOL CONFIGURATION  (from Toggle-Protocols.ps1)
# =============================================================================
# SCHANNEL is the Windows secure channel for TLS/SSL. Registry edits control
# which protocol versions are enabled. Hardening disables SSL 2.0, SSL 3.0,
# TLS 1.0, and TLS 1.1 (all vulnerable); lab simulation re-enables them.

PROTOCOLS = {
    "SSL 2.0": ("SSL 2.0", ["Enabled", "DisabledByDefault"], True),  # always disable
    "SSL 3.0": ("SSL 3.0", ["Enabled", "DisabledByDefault"], False),  # POODLE
    "TLS 1.0": ("TLS 1.0", ["Enabled", "DisabledByDefault"], False),  # BEAST
    "TLS 1.1": ("TLS 1.1", ["Enabled", "DisabledByDefault"], False),  # legacy
    "TLS 1.2": ("TLS 1.2", ["Enabled", "DisabledByDefault"], False),  # modern
}

SCHANNEL_PROTOCOL_PATH = r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"


def _protocol_registry_command(protocol: str, secure: bool) -> str:
    """Generate a PowerShell command to set a protocol's Enabled/DisabledByDefault."""
    if secure:
        # Hardening: disable deprecated/vulnerable protocols
        if protocol == "TLS 1.2":
            enable_value, disabled_default = 1, 0  # TLS 1.2 always enabled
        else:
            enable_value, disabled_default = 0, 1  # everything else disabled
    else:
        # Lab simulation: enable all protocols (vulnerable config)
        enable_value, disabled_default = 1, 0

    server_path = f"{SCHANNEL_PROTOCOL_PATH}\\{protocol}\\Server"
    client_path = f"{SCHANNEL_PROTOCOL_PATH}\\{protocol}\\Client"

    # Use PowerShell to create registry keys and set DWord values
    cmd_parts = [
        f"New-Item -Path '{server_path}' -Force | Out-Null",
        f"New-Item -Path '{client_path}' -Force | Out-Null",
        f"New-ItemProperty -Path '{server_path}' -Name 'Enabled' -Value {enable_value} -PropertyType 'DWord' -Force | Out-Null",
        f"New-ItemProperty -Path '{server_path}' -Name 'DisabledByDefault' -Value {disabled_default} -PropertyType 'DWord' -Force | Out-Null",
        f"New-ItemProperty -Path '{client_path}' -Name 'Enabled' -Value {enable_value} -PropertyType 'DWord' -Force | Out-Null",
        f"New-ItemProperty -Path '{client_path}' -Name 'DisabledByDefault' -Value {disabled_default} -PropertyType 'DWord' -Force | Out-Null",
    ]
    # Chain commands with semicolons for a single PowerShell invocation
    return "powershell -Command \"" + "; ".join(cmd_parts) + "\""


def protocols(secure: bool = True, dry_run: bool = False) -> None:
    """Configure TLS/SSL protocols via Windows SCHANNEL registry.

    Args:
        secure: If True, disable deprecated/vulnerable protocols and keep TLS 1.2.
                If False, enable all protocols for lab vulnerability simulation.
    """
    mode = "SECURE (hardening)" if secure else "INSECURE (lab simulation)"
    print(f"[*] Configuring protocols to {mode}...")

    commands = [
        _protocol_registry_command(proto, secure)
        for proto in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"]
    ]
    run_all(commands, dry_run=dry_run)
    print("[!] Reboot required for protocol changes to take effect.")


# =============================================================================
# CIPHER SUITE CONFIGURATION  (from Toggle-CipherSuites.ps1)
# =============================================================================
# Windows SCHANNEL cipher suite order is written to a single registry value
# at HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002

SECURE_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
]

INSECURE_CIPHERS_TO_ADD = [
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
]

CIPHER_SUITE_REG_PATH = r"HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"


def cipher_suites(secure: bool = True, dry_run: bool = False) -> None:
    """Configure Windows SCHANNEL cipher suite order.

    Args:
        secure: If True, enforce modern ciphers (ECDHE/DHE + AES-GCM, no RC4/DES).
                If False, add insecure ciphers (RC4, DES, export-grade) for lab testing.
    """
    mode = "SECURE (hardening)" if secure else "INSECURE (lab simulation)"
    print(f"[*] Configuring cipher suites to {mode}...")

    if secure:
        cipher_order = ",".join(SECURE_CIPHERS)
    else:
        cipher_order = ",".join(SECURE_CIPHERS + INSECURE_CIPHERS_TO_ADD)

    # PowerShell command to write cipher suite order to registry
    ps_cmd = (
        f"New-Item -Path '{CIPHER_SUITE_REG_PATH}' -Force | Out-Null; "
        f"Set-ItemProperty -Path '{CIPHER_SUITE_REG_PATH}' -Name 'Functions' "
        f"-Value '{cipher_order}'; "
        f"Set-ItemProperty -Path '{CIPHER_SUITE_REG_PATH}' -Name 'Enabled' -Value 1"
    )
    run(f"powershell -Command \"{ps_cmd}\"", dry_run=dry_run)
    print("[!] Reboot required for cipher suite changes to take effect.")


# =============================================================================
# GUEST ACCOUNT ACCESS CONTROL  (from Toggle-GuestAccount.ps1)
# =============================================================================
# The built-in Guest account in the Administrators group is a privilege
# escalation / lateral movement vector. CIS benchmarks require removing it.

def guest_remove_from_admins(dry_run: bool = False) -> None:
    """Remove the Guest account from the local Administrators group (hardening).

    This is the CIS benchmark recommendation to prevent unauthenticated
    privilege escalation via the built-in Guest account.
    """
    ps_cmd = (
        "If (Get-LocalGroupMember -Group 'Administrators' -Member 'Guest' -ErrorAction SilentlyContinue) { "
        "Remove-LocalGroupMember -Group 'Administrators' -Member 'Guest'; "
        "Write-Output '[+] Guest removed from Administrators.' "
        "} Else { "
        "Write-Output '[!] Guest not a member of Administrators.' "
        "}"
    )
    run(f"powershell -Command \"{ps_cmd}\"", dry_run=dry_run)


def guest_add_to_admins(dry_run: bool = False) -> None:
    """Add the Guest account to the local Administrators group (lab simulation only).

    Use only to simulate a privilege escalation misconfiguration in a test environment.
    """
    ps_cmd = (
        "If (-not (Get-LocalGroupMember -Group 'Administrators' -Member 'Guest' -ErrorAction SilentlyContinue)) { "
        "Add-LocalGroupMember -Group 'Administrators' -Member 'Guest'; "
        "Write-Output '[+] Guest added to Administrators (lab mode).' "
        "} Else { "
        "Write-Output '[!] Guest already a member of Administrators.' "
        "}"
    )
    run(f"powershell -Command \"{ps_cmd}\"", dry_run=dry_run)


# =============================================================================
# CLI
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lab_hardening.py",
        description="Windows security hardening toolkit for the OSSEC HIDS lab. "
                    "Configures audit policy, TLS/cipher suite, protocols, and "
                    "guest account access. WINDOWS ONLY.",
    )
    p.add_argument("--dry-run", action="store_true",
                   help="print commands without executing them")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Audit policy
    sub.add_parser("audit-enable", help="enable all critical audit policy categories")
    sub.add_parser("audit-disable", help="disable all audit policy (reverse hardening)")

    # Protocols
    sp = sub.add_parser("protocols", help="configure TLS/SSL protocols")
    sp.add_argument("--secure", dest="secure", action="store_true", default=True,
                    help="disable deprecated/vulnerable protocols (default, hardening)")
    sp.add_argument("--insecure", dest="secure", action="store_false",
                    help="enable all protocols (lab simulation only)")

    # Cipher suites
    sp = sub.add_parser("cipher-suites", help="configure SCHANNEL cipher suite order")
    sp.add_argument("--secure", dest="secure", action="store_true", default=True,
                    help="enforce modern ciphers (default, hardening)")
    sp.add_argument("--insecure", dest="secure", action="store_false",
                    help="add insecure ciphers (lab simulation only)")

    # Guest account
    sp = sub.add_parser("guest-remove", help="remove Guest from Administrators (hardening)")
    sp = sub.add_parser("guest-add", help="add Guest to Administrators (lab simulation)")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    d = args.dry_run

    dispatch = {
        "audit-enable": lambda: audit_enable(d),
        "audit-disable": lambda: audit_disable(d),
        "protocols": lambda: protocols(args.secure, d),
        "cipher-suites": lambda: cipher_suites(args.secure, d),
        "guest-remove": lambda: guest_remove_from_admins(d),
        "guest-add": lambda: guest_add_to_admins(d),
    }

    try:
        dispatch[args.cmd]()
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
