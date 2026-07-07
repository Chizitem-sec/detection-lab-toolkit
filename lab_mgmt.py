#!/usr/bin/env python3
"""
lab_mgmt.py — Lab Management Toolkit
=============================================================================
Author  : Johnbosco (Chizitem) Ibeneme
Purpose : Management and provisioning operations for the OSSEC HIDS lab and
          the Gophish phishing-simulation lab. These are the state-CHANGING
          operations — installing dependencies, deploying the OSSEC Web UI,
          registering agents, managing services, and standing up Gophish
          infrastructure. (The read-only OSSEC/Apache/syslog analysis
          operations live in the companion file, lab_monitoring.py.)

Scope   : Blue-team lab infrastructure only. Consolidates the bash command
          libraries used to build and troubleshoot two home labs:
            - OSSEC HIDS on Ubuntu 24.04 (server + Windows 11 agent)
            - Gophish phishing simulation on macOS (localhost + ngrok + Mailgun)

Design  : Each documented lab procedure is exposed as a subcommand. Every
          shell action runs through a single run() helper that supports
          --dry-run (print the command without executing) so the tool is safe
          to demonstrate and read. Nothing here disables a security control
          or generates an offensive payload.

Usage   : python3 lab_mgmt.py --help
          python3 lab_mgmt.py ossec-install-deps --dry-run
          python3 lab_mgmt.py apache-switch-php --from 8.3 --to 7.4
          python3 lab_mgmt.py service restart apache2

Requires: Python 3.8+, an Ubuntu/Debian host for the OSSEC procedures,
          sudo/root for most operations.
=============================================================================
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from dataclasses import dataclass


# =============================================================================
# CORE HELPER — every shell action funnels through here
# =============================================================================

@dataclass
class RunResult:
    command: str
    returncode: int
    stdout: str
    stderr: str


def run(command: str, *, dry_run: bool = False, check: bool = False,
        capture: bool = False) -> RunResult:
    """Execute a shell command with consistent logging and dry-run support.

    Args:
        command:  The shell command to run.
        dry_run:  If True, print the command and skip execution. This is what
                  makes the toolkit safe to demo and easy to read.
        check:    If True, raise on a non-zero exit code.
        capture:  If True, capture stdout/stderr instead of streaming them.

    Returns:
        RunResult with the command, exit code, and any captured output.
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
    """Run a sequence of commands in order, stopping on the first failure."""
    for cmd in commands:
        result = run(cmd, dry_run=dry_run)
        if not dry_run and result.returncode != 0:
            print(f"  ! stopped: previous command exited {result.returncode}",
                  file=sys.stderr)
            break


# =============================================================================
# PACKAGE MANAGEMENT  (from package-management.sh)
# =============================================================================

# Build dependencies required to compile OSSEC v4.0.0 from source on Ubuntu 24.04.
# libssl1.0-dev does NOT exist on 24.04 — libssl-dev is the correct replacement.
OSSEC_BUILD_DEPS = [
    "php", "php-cli", "php-common", "libapache2-mod-php",
    "apache2", "apache2-utils", "sendmail", "inotify-tools",
    "build-essential", "gcc", "make", "wget", "tar",
    "libz-dev", "libssl-dev",
]

# Dependencies discovered mid-build once compilation errors surfaced:
#   pcre2.h missing  -> libpcre2-dev  (OSSEC's regex engine needs PCRE2)
#   cannot find -lsystemd -> libsystemd-dev  (mail daemon links against systemd)
OSSEC_MISSING_DEPS = ["libpcre2-dev", "libsystemd-dev"]


def apt_update_upgrade(dry_run: bool = False) -> None:
    """Refresh the apt index and upgrade installed packages."""
    run_all(["sudo apt update", "sudo apt upgrade -y"], dry_run=dry_run)


def ossec_install_deps(dry_run: bool = False) -> None:
    """Install all build dependencies to compile OSSEC from source on Ubuntu 24.04.

    Installs the core toolchain plus the two dependencies (libpcre2-dev,
    libsystemd-dev) that were missing from the initial install and caused
    OSSEC build failures.
    """
    run("sudo apt update", dry_run=dry_run)
    pkgs = " ".join(OSSEC_BUILD_DEPS + OSSEC_MISSING_DEPS)
    run(f"sudo apt install -y {pkgs}", dry_run=dry_run)


def install_php74_ppa(dry_run: bool = False) -> None:
    """Add the Ondrej PPA and install PHP 7.4 alongside the system PHP 8.x.

    Required because the OSSEC WUI (v0.8) uses curly-brace array/string-offset
    syntax that PHP 8.0 removed. Ubuntu 24.04 ships PHP 8.3 by default; the
    Ondrej PPA backports 7.4.
    """
    run_all([
        "sudo add-apt-repository ppa:ondrej/php -y",
        "sudo apt update",
        "sudo apt install php7.4 libapache2-mod-php7.4 -y",
    ], dry_run=dry_run)


# =============================================================================
# APACHE + PHP  (from apache-and-php.sh)
# =============================================================================

def apache_switch_php(php_from: str, php_to: str, dry_run: bool = False) -> None:
    """Switch the active Apache PHP module (only one can be active at a time).

    The OSSEC WUI required PHP 7.4; Ubuntu 24.04's default PHP 8.3 produced a
    fatal 'curly braces no longer supported' error and a blank WUI body.
    """
    run_all([
        f"sudo a2dismod php{php_from}",
        f"sudo a2enmod php{php_to}",
        "sudo systemctl restart apache2",
        "apache2ctl -M | grep php",   # verify which module is active
    ], dry_run=dry_run)


def apache_enable_rewrite(dry_run: bool = False) -> None:
    """Enable mod_rewrite (required by the OSSEC WUI .htaccess rules)."""
    run_all([
        "sudo a2enmod rewrite",
        "sudo systemctl restart apache2",
    ], dry_run=dry_run)


def deploy_ossec_wui(dry_run: bool = False) -> None:
    """Clone, deploy, and fix permissions on the OSSEC Web UI under Apache.

    Clones the WUI into /tmp, moves it to the web root, removes the default
    Apache index page, runs setup.sh, then sets www-data ownership and 755
    permissions so Apache can read the files.
    """
    run_all([
        "cd /tmp && git clone https://github.com/ossec/ossec-wui.git",
        "sudo mv /tmp/ossec-wui/ /var/www/html/",
        "sudo rm -f /var/www/html/index.html",
        "sudo chmod +x /var/www/html/ossec-wui/setup.sh",
        # setup.sh is interactive (admin user, password, www-data) — run manually:
        "echo 'Now run: cd /var/www/html/ossec-wui && ./setup.sh'",
        "sudo chown -R www-data:www-data /var/www/html/ossec-wui",
        "sudo chmod -R 755 /var/www/html/ossec-wui",
        "sudo systemctl restart apache2",
    ], dry_run=dry_run)


def apache_configtest(dry_run: bool = False) -> None:
    """Validate Apache config syntax before restarting."""
    run("sudo apache2ctl configtest", dry_run=dry_run)


# =============================================================================
# SERVICE CONTROL  (from service-control.sh)
# =============================================================================

_SYSTEMCTL_ACTIONS = {"start", "stop", "restart", "reload",
                      "enable", "disable", "status"}


def service(action: str, name: str, dry_run: bool = False) -> None:
    """Manage a systemd service (Apache, and other systemd-managed units).

    Note: OSSEC is NOT systemd-managed — use the ossec() function for it.
    """
    if action not in _SYSTEMCTL_ACTIONS:
        raise ValueError(f"action must be one of {sorted(_SYSTEMCTL_ACTIONS)}")
    run(f"sudo systemctl {action} {shlex.quote(name)}", dry_run=dry_run)


def ossec(action: str, dry_run: bool = False) -> None:
    """Control the OSSEC daemons via ossec-control (OSSEC's own control script).

    Manages: ossec-execd, ossec-analysisd, ossec-logcollector, ossec-remoted,
    ossec-syscheckd, ossec-monitord. Restart is required after any ossec.conf
    change. For agent communication, confirm ossec-remoted is running.
    """
    if action not in {"start", "stop", "restart", "status"}:
        raise ValueError("ossec action must be start|stop|restart|status")
    run(f"sudo /var/ossec/bin/ossec-control {action}", dry_run=dry_run)


# =============================================================================
# APPARMOR  (from apparmor.sh)
# =============================================================================
# In the OSSEC lab, AppArmor repeatedly denied Firefox's snap profile access to
# /proc/pressure/memory. OSSEC's log collector picked up those syslog denials
# and fired hundreds of Rule 52002 (AppArmor DENIED) Level 3 alerts, flooding
# the WUI and burying real attack detections. Complain mode (or stopping
# AppArmor in the isolated lab VM) cleaned up the alert feed.

FIREFOX_SNAP_PROFILE = "/snap/firefox/current/usr/lib/firefox/firefox"


def apparmor_complain(profile: str, dry_run: bool = False) -> None:
    """Put an AppArmor profile into complain mode (log violations, don't block).

    Used on the Firefox snap profile to stop the /proc/pressure/memory denials
    from flooding OSSEC's alert feed, without fully disabling AppArmor.
    """
    run(f"sudo aa-complain {shlex.quote(profile)}", dry_run=dry_run)


def apparmor_enforce(profile: str, dry_run: bool = False) -> None:
    """Return an AppArmor profile to enforce mode after complain-mode testing."""
    run(f"sudo aa-enforce {shlex.quote(profile)}", dry_run=dry_run)


def apparmor_disable(dry_run: bool = False) -> None:
    """Stop and disable AppArmor. ISOLATED LAB VMs ONLY — never in production.

    Justified in the lab only because AppArmor denials were drowning the
    detection signal the lab existed to observe.
    """
    run_all([
        "sudo systemctl stop apparmor",
        "sudo systemctl disable apparmor",
    ], dry_run=dry_run)


# =============================================================================
# OSSEC AGENT MANAGEMENT  (from ossec-management.sh)
# =============================================================================

def ossec_list_agents(dry_run: bool = False) -> None:
    """List registered OSSEC agents and their connection status.

    Active = connected and sending heartbeats. Disconnected = registered but
    silent (check IP, firewall, or a bad key). In the lab, agent 001 (Win11,
    192.168.64.9) should show Active alongside 000 (local server).
    """
    run("sudo /var/ossec/bin/agent_control -lc", dry_run=dry_run)


def ossec_integrity_check(agent_id: str | None = None,
                          dry_run: bool = False) -> None:
    """Trigger an immediate integrity/rootkit check (all agents, or one by ID)."""
    if agent_id:
        run(f"sudo /var/ossec/bin/agent_control -r -u {shlex.quote(agent_id)}",
            dry_run=dry_run)
    else:
        run("sudo /var/ossec/bin/agent_control -r -a", dry_run=dry_run)


def ossec_validate_config(dry_run: bool = False) -> None:
    """Validate ossec.conf before restarting the daemons."""
    run("sudo /var/ossec/bin/ossec-analysisd -t", dry_run=dry_run)


def ossec_register_agent_help() -> None:
    """Print the interactive manage_agents workflow used to register the agent.

    manage_agents is interactive, so it can't be safely scripted end-to-end.
    This prints the exact steps used in the lab.
    """
    print(__doc__ and "")  # spacing
    print("""OSSEC agent registration (interactive — run manually as root):

    sudo -i
    cd /var/ossec/bin
    ./manage_agents

  Inside manage_agents:
    A  Add agent   -> name: Win11 | IP: 192.168.64.9 | ID: 001 | confirm: y
    E  Extract key -> enter 001, copy the base64 key string
    L  List agents
    R  Remove agent
    Q  Quit

  Then paste the extracted key into the OSSEC Agent Manager on the Windows host.""")


# =============================================================================
# FILE OPERATIONS  (from file-operations.sh)
# =============================================================================

def extract_archive(path: str, dest: str | None = None,
                     dry_run: bool = False) -> None:
    """Extract a .tar.gz source archive (e.g. ossec-hids-4.0.0.tar.gz)."""
    cmd = f"tar xzvf {shlex.quote(path)}"
    if dest:
        cmd += f" -C {shlex.quote(dest)}"
    run(cmd, dry_run=dry_run)


def backup_file(path: str, dry_run: bool = False) -> None:
    """Copy a config file to a .bak before editing it (always back up first).

    Standard practice before touching ossec.conf or an Apache site config.
    """
    run(f"sudo cp {shlex.quote(path)} {shlex.quote(path)}.bak", dry_run=dry_run)


def serve_directory(directory: str, port: int = 8080,
                    dry_run: bool = False) -> None:
    """Host a directory over HTTP for cross-VM file transfer (no shared folders).

    The server serves whatever directory you point it at. Used in the lab to
    move the Windows OSSEC agent installer to the Win11 VM. Port 8080 avoids
    Apache on 80.
    """
    run(f"cd {shlex.quote(directory)} && python3 -m http.server {int(port)}",
        dry_run=dry_run)


def stop_http_server(port: int = 8080, dry_run: bool = False) -> None:
    """Stop a background python http.server (by process match or port)."""
    run("pkill -f http.server || true", dry_run=dry_run)
    run(f"sudo kill -9 $(lsof -t -i:{int(port)}) 2>/dev/null || true",
        dry_run=dry_run)


# =============================================================================
# GOPHISH INFRASTRUCTURE  (from gophish-infrastructure.sh)
# =============================================================================
# Authorized phishing SIMULATION only, with explicit consent from all targets.
# Lab topology: Gophish admin on 127.0.0.1:3333, phishing site on :80 exposed
# via an ngrok HTTPS tunnel, Mailgun SMTP relay on :587 for delivery (Railway
# blocked outbound port 25).

def gophish_build(dry_run: bool = False) -> None:
    """Clone and build the Gophish binary from source with Go."""
    run_all([
        "git clone https://github.com/gophish/gophish.git",
        "cd gophish && go build .",
        "ls -lh gophish/gophish",
    ], dry_run=dry_run)


def gophish_start(background: bool = False, dry_run: bool = False) -> None:
    """Launch Gophish. On first run it prints the admin URL and temp password.

    Run from the directory containing the gophish binary. Admin panel binds to
    127.0.0.1:3333 (local only); the phishing site binds to :80.
    """
    if background:
        run("sudo ./gophish > gophish.log 2>&1 &", dry_run=dry_run)
    else:
        run("sudo ./gophish", dry_run=dry_run)


def ngrok_tunnel(port: int = 80, dry_run: bool = False) -> None:
    """Open an ngrok HTTPS tunnel to the local Gophish phishing site.

    The public https URL ngrok prints is what goes in the campaign's URL field.
    Free-tier URLs change on every restart — update the campaign accordingly.
    """
    run(f"ngrok http {int(port)}", dry_run=dry_run)


def test_smtp(host: str = "smtp.mailgun.org", port: int = 587,
              dry_run: bool = False) -> None:
    """Confirm the Mailgun SMTP relay port is reachable before configuring Gophish.

    Railway blocked outbound port 25, so the lab used Mailgun's authenticated
    relay on 587 (STARTTLS) instead.
    """
    run(f"nc -zv {shlex.quote(host)} {int(port)}", dry_run=dry_run)


# =============================================================================
# CLI
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lab_mgmt.py",
        description="Management/provisioning toolkit for the OSSEC HIDS and "
                    "Gophish labs (state-changing operations).",
    )
    p.add_argument("--dry-run", action="store_true",
                   help="print commands without executing them")
    sub = p.add_subparsers(dest="cmd", required=True)

    # package / dependency
    sub.add_parser("apt-update", help="apt update && upgrade")
    sub.add_parser("ossec-install-deps",
                   help="install OSSEC build dependencies (Ubuntu 24.04)")
    sub.add_parser("install-php74", help="add Ondrej PPA and install PHP 7.4")

    # apache
    sp = sub.add_parser("apache-switch-php", help="switch active Apache PHP module")
    sp.add_argument("--from", dest="php_from", required=True)
    sp.add_argument("--to", dest="php_to", required=True)
    sub.add_parser("apache-enable-rewrite", help="enable mod_rewrite")
    sub.add_parser("deploy-ossec-wui", help="clone/deploy the OSSEC Web UI")
    sub.add_parser("apache-configtest", help="validate Apache config syntax")

    # services
    sp = sub.add_parser("service", help="systemd service control")
    sp.add_argument("action", choices=sorted(_SYSTEMCTL_ACTIONS))
    sp.add_argument("name")
    sp = sub.add_parser("ossec", help="OSSEC daemon control")
    sp.add_argument("action", choices=["start", "stop", "restart", "status"])

    # apparmor
    sp = sub.add_parser("apparmor-complain", help="profile -> complain mode")
    sp.add_argument("--profile", default=FIREFOX_SNAP_PROFILE)
    sp = sub.add_parser("apparmor-enforce", help="profile -> enforce mode")
    sp.add_argument("--profile", default=FIREFOX_SNAP_PROFILE)
    sub.add_parser("apparmor-disable", help="stop+disable AppArmor (lab VM only)")

    # ossec agents
    sub.add_parser("ossec-list-agents", help="list agents + status")
    sp = sub.add_parser("ossec-integrity", help="run integrity/rootkit check")
    sp.add_argument("--agent-id", default=None)
    sub.add_parser("ossec-validate-config", help="validate ossec.conf")
    sub.add_parser("ossec-register-help", help="print agent-registration steps")

    # files
    sp = sub.add_parser("extract", help="extract a .tar.gz archive")
    sp.add_argument("path")
    sp.add_argument("--dest", default=None)
    sp = sub.add_parser("backup", help="copy a file to .bak before editing")
    sp.add_argument("path")
    sp = sub.add_parser("serve", help="host a directory over HTTP")
    sp.add_argument("directory")
    sp.add_argument("--port", type=int, default=8080)
    sp = sub.add_parser("stop-serve", help="stop a python http.server")
    sp.add_argument("--port", type=int, default=8080)

    # gophish
    sub.add_parser("gophish-build", help="clone + build Gophish")
    sp = sub.add_parser("gophish-start", help="launch Gophish")
    sp.add_argument("--background", action="store_true")
    sp = sub.add_parser("ngrok", help="open ngrok tunnel to phishing site")
    sp.add_argument("--port", type=int, default=80)
    sp = sub.add_parser("test-smtp", help="test Mailgun SMTP reachability")
    sp.add_argument("--host", default="smtp.mailgun.org")
    sp.add_argument("--port", type=int, default=587)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    d = args.dry_run

    dispatch = {
        "apt-update": lambda: apt_update_upgrade(d),
        "ossec-install-deps": lambda: ossec_install_deps(d),
        "install-php74": lambda: install_php74_ppa(d),
        "apache-switch-php": lambda: apache_switch_php(args.php_from, args.php_to, d),
        "apache-enable-rewrite": lambda: apache_enable_rewrite(d),
        "deploy-ossec-wui": lambda: deploy_ossec_wui(d),
        "apache-configtest": lambda: apache_configtest(d),
        "service": lambda: service(args.action, args.name, d),
        "ossec": lambda: ossec(args.action, d),
        "apparmor-complain": lambda: apparmor_complain(args.profile, d),
        "apparmor-enforce": lambda: apparmor_enforce(args.profile, d),
        "apparmor-disable": lambda: apparmor_disable(d),
        "ossec-list-agents": lambda: ossec_list_agents(d),
        "ossec-integrity": lambda: ossec_integrity_check(args.agent_id, d),
        "ossec-validate-config": lambda: ossec_validate_config(d),
        "ossec-register-help": ossec_register_agent_help,
        "extract": lambda: extract_archive(args.path, args.dest, d),
        "backup": lambda: backup_file(args.path, d),
        "serve": lambda: serve_directory(args.directory, args.port, d),
        "stop-serve": lambda: stop_http_server(args.port, d),
        "gophish-build": lambda: gophish_build(d),
        "gophish-start": lambda: gophish_start(args.background, d),
        "ngrok": lambda: ngrok_tunnel(args.port, d),
        "test-smtp": lambda: test_smtp(args.host, args.port, d),
    }

    try:
        dispatch[args.cmd]()
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
