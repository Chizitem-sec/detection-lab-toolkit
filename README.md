# OSSEC & Gophish Lab Toolkit

![CI](https://github.com/Chizitem-sec/detection-lab-toolkit/actions/workflows/ci.yml/badge.svg)

Operational command-line tools for blue-team security lab environments. Consolidated Python CLIs for OSSEC HIDS deployment, monitoring, and hardening on Ubuntu/Debian + Windows 11. Built from production bash and PowerShell scripts used in home lab attack simulation and detection exercises.

## Overview

This toolkit documents three areas of hands-on security lab work:

1. **Lab Provisioning & Automation** (`lab_mgmt.py`) — deploying OSSEC server, configuring Apache + PHP, managing agents, setting up Gophish infrastructure
2. **Detection & Analysis** (`lab_monitoring.py`) — monitoring OSSEC alerts live, searching by rule/event, analyzing Apache/auth logs for attack signatures
3. **Windows Security Hardening** (`lab_hardening.py`) — audit policy configuration, TLS/protocol hardening, cipher suite enforcement, guest account access control

## Quick Start

```bash
# View available commands
python3 lab_mgmt.py --help
python3 lab_monitoring.py --help
python3 lab_hardening.py --help

# Dry-run a command (print without executing)
python3 lab_mgmt.py --dry-run ossec-install-deps
python3 lab_monitoring.py --dry-run alerts-follow
python3 lab_hardening.py --dry-run audit-enable

# Execute for real
python3 lab_mgmt.py apache-enable-rewrite
python3 lab_monitoring.py alerts-rule 18101
python3 lab_hardening.py protocols --secure
```

## Tools

### `lab_mgmt.py` — Management & Provisioning

State-changing operations for lab infrastructure setup and configuration.

**Platforms:** Ubuntu 24.04 / Debian-based Linux

**Key Commands:**
- `apt-update`, `ossec-install-deps`, `install-php74` — dependency management
- `apache-switch-php`, `apache-enable-rewrite`, `deploy-ossec-wui` — Apache/PHP/OSSEC WUI
- `service`, `ossec` — systemd and OSSEC daemon control
- `apparmor-complain`, `apparmor-enforce`, `apparmor-disable` — AppArmor profile modes
- `ossec-list-agents`, `ossec-integrity`, `ossec-register-help` — OSSEC agent management
- `extract`, `backup`, `serve` — file operations and HTTP hosting
- `gophish-build`, `gophish-start`, `ngrok`, `test-smtp` — Gophish phishing-simulation infrastructure

**Lab Context:**
The OSSEC WUI (v0.8) required PHP 7.4 but Ubuntu 24.04 shipped PHP 8.3, which removed curly-brace array syntax and produced fatal errors. `apache-switch-php --from 8.3 --to 7.4` fixed this via the Ondrej PPA and module switching. AppArmor denial events were flooding the alert feed, so `apparmor-complain` suppressed those signals without disabling the security module entirely.

### `lab_monitoring.py` — Log Analysis & Detection Monitoring

Read-only analysis of OSSEC alerts, Windows events, and system logs. Useful during attack simulation and post-event forensics.

**Platforms:** Ubuntu 24.04 / Debian-based Linux (for OSSEC log paths); Windows (for Event Viewer/auth log context)

**Key Commands:**
- `alerts-follow`, `alerts-tail`, `alerts-rule`, `alerts-event` — OSSEC alert stream analysis
- `alerts-high`, `alerts-windows`, `alerts-search` — severity/type/text filtering
- `top-rules` — identify the most frequently triggered detection rules
- `apache-error`, `apache-php-errors` — web server diagnostics
- `auth-failed`, `auth-sudo`, `auth-ssh` — authentication event tracking
- `syslog-apparmor`, `syslog-apparmor-counts` — security module monitoring
- `gophish-results`, `ngrok-status` — phishing campaign tracking

**Lab Context:**
During Meterpreter post-exploitation (user creation via `net user hacked /add`, RDP enablement, privilege escalation), the OSSEC alert log captured Windows Event IDs 4720 (user created), 4732 (group membership changed), and 7040 (service startup mode). Rule 18101 (Windows account events) fired at Level 8, confirming detection of the simulated attack chain. The `top-rules` command revealed that AppArmor DENIED events (Rule 52002) were the loudest signal in the alert feed, so those were suppressed separately.

### `lab_hardening.py` — Windows Security Hardening

Configuration of Windows audit policies, TLS/SSL protocols, cipher suites, and guest account access control via `auditpol` and SCHANNEL registry operations.

**Platforms:** Windows 11 / Windows Server (requires Administrator privileges)

**Key Commands:**
- `audit-enable`, `audit-disable` — enable/disable Windows audit policy categories (Account Management, Logon/Logoff, Policy Change, Privilege Use, System)
- `protocols --secure`, `protocols --insecure` — disable/enable SSL 2.0, SSL 3.0, TLS 1.0/1.1 (hardening vs. lab simulation)
- `cipher-suites --secure`, `cipher-suites --insecure` — enforce modern ciphers (ECDHE/DHE + AES-GCM) or add legacy weak ciphers (RC4, DES, export-grade)
- `guest-remove`, `guest-add` — remove/add Guest account from Administrators group

**Lab Context:**
Windows 11's default audit policy does not log Account Management events. Running `audit-enable` caused Event ID 4720 (user created) to appear in Windows Event Viewer when `net user hacked /add` was executed via Meterpreter, allowing OSSEC to detect and alert on the backdoor account creation. Protocol and cipher suite hardening scripts allow creation of deliberately vulnerable configurations for testing vulnerability scanners and compliance assessment tools.

## Continuous Integration

Every push and pull request runs a GitHub Actions pipeline (`.github/workflows/ci.yml`) with three jobs:

1. **Lint** — `flake8` against all three CLI modules. Config in `.flake8` (line-length raised to 145 to accommodate a handful of long PowerShell/SCHANNEL registry command strings that would be less readable if wrapped; one continuation-indent style rule disabled).
2. **Test** — `pytest` runs 50 tests across Python 3.10, 3.11, and 3.12. Tests mock `subprocess.run` to guarantee `--dry-run` never touches a real system, verify command construction and ordering (e.g. `a2dismod` runs before `a2enmod` when switching PHP versions), confirm shell arguments are safely quoted, and check the security-critical logic in `lab_hardening.py` (secure mode actually disables deprecated protocols and excludes weak ciphers; insecure/lab mode does the opposite).
3. **Dry-run validation** — invokes each CLI's `--help` and a representative set of real subcommands under `--dry-run`, then introspects each `argparse` parser to confirm every registered subcommand is reachable. This catches CLI-wiring bugs that unit tests calling functions directly can miss.

Run the same checks locally before pushing:

```bash
pip install -r requirements-dev.txt
flake8 lab_mgmt.py lab_monitoring.py lab_hardening.py
pytest tests/ -v
```

## Requirements

- **Python 3.8+**
- **`lab_mgmt.py`**: Ubuntu 24.04 / Debian-based Linux, `sudo`/root access
- **`lab_monitoring.py`**: Ubuntu/Debian (for OSSEC paths), standard GNU utilities (`tail`, `grep`, `awk`)
- **`lab_hardening.py`**: Windows 11 / Windows Server, **Administrator privileges**, PowerShell 5.1+

## Architecture

All three tools support `--dry-run` mode, which prints commands without executing them. This is useful for reading the toolkit without actually modifying system state, and for demonstrating the toolkit's logic.

Each tool uses a single `run()` helper function that wraps `subprocess` calls with consistent logging and error handling. State-changing commands (`lab_mgmt.py`) use `check=False` by default to continue on recoverable failures; read-only commands (`lab_monitoring.py`) stream output directly to the terminal for interactive use.

## Lab Story

This toolkit documents a complete OSSEC HIDS lab environment:

1. **Provisioning Phase** — Install OSSEC from source on Ubuntu 24.04, deploy the WUI, resolve PHP 8 compatibility issues, register a Windows 11 agent
2. **Hardening Phase** — Configure Windows audit policy and disable weak TLS protocols to meet the detection substrate requirements
3. **Attack Simulation Phase** — Use Metasploit to generate a reverse TCP payload, deliver it to the Windows agent, establish a Meterpreter session
4. **Post-Exploitation Phase** — Create a backdoor user account (`net user hacked /add`), add it to Administrators, enable RDP, modify service startup configuration
5. **Detection Phase** — Monitor OSSEC alert stream in real time, confirm that Windows Event IDs 4720 (user created), 4732 (privilege change), and 7040 (service state) are detected as Rule 18101 Level 8 alerts

The toolkit captures the provisioning, monitoring, and hardening components of this workflow. The attack simulation itself (payload generation, delivery, post-exploitation) is documented but not included as code to maintain the defensive posture of this portfolio artifact.

## Usage Examples

### Start the OSSEC WUI after a fresh install

```bash
python3 lab_mgmt.py --dry-run deploy-ossec-wui
# Review the commands, then:
python3 lab_mgmt.py deploy-ossec-wui
# You'll be prompted to run setup.sh manually for the admin password
```

### Watch OSSEC alerts during an attack simulation

```bash
python3 lab_monitoring.py alerts-follow
# Ctrl+C to stop tailing
```

### Find all user-creation alerts (Event ID 4720 → Rule 18101)

```bash
python3 lab_monitoring.py alerts-event 4720
```

### Identify alert noise (most frequently triggered rules)

```bash
python3 lab_monitoring.py top-rules --limit 10
```

### Configure Windows audit policy on an agent

```bash
# On Windows 11 as Administrator:
python3 lab_hardening.py audit-enable
```

### Harden TLS protocols (disable SSL 3.0, TLS 1.0/1.1)

```bash
# On Windows as Administrator:
python3 lab_hardening.py protocols --secure
# Reboot required for changes to take effect
```

### Simulate a vulnerable protocol configuration for testing

```bash
python3 lab_hardening.py protocols --insecure --dry-run
# This would enable all protocols (lab simulation only)
```

## Conversion Notes

This toolkit was originally developed as bash scripts (for Ubuntu/Debian) and PowerShell scripts (for Windows). The Python versions consolidate these into cross-platform CLIs while preserving the original structure and documentation.

**Bash → Python (`lab_mgmt.py`, `lab_monitoring.py`):**
- Package management commands (`apt`, `apt-get`)
- Service control (`systemctl`, `ossec-control`)
- File operations (`tar`, `chmod`, `chown`, `python3 http.server`)
- Log tailing and grep-based analysis

**PowerShell → Python (`lab_hardening.py`):**
- Windows audit policy (`auditpol /set /category:...`)
- SCHANNEL registry operations (protocol and cipher suite configuration)
- Local group membership management (`Get-LocalGroupMember`, `Add-LocalGroupMember`, `Remove-LocalGroupMember`)

All original commentary, lab-specific context (IP addresses, hostnames, Event IDs), and error-resolution notes are preserved in docstrings.

## Author

Johnbosco (Chizitem) Ibeneme  
Cybersecurity Specialist Intern, disruptiveOps  
M.S. Cybersecurity, Washington University of Science and Technology (2026)

## License

These scripts are provided as-is for educational and authorized lab use only. Use at your own risk in controlled environments.

---

**Keywords:** `ossec`, `grc`, `blue-team`, `detection`, `hids`, `windows-hardening`, `lab`, `ubuntu`, `siem`, `audit-policy`, `tls-hardening`, `gophish`, `security-automation`
