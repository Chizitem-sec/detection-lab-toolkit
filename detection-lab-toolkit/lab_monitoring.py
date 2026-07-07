#!/usr/bin/env python3
"""
lab_monitoring.py — Lab Monitoring & Log-Analysis Toolkit
=============================================================================
Author  : Johnbosco (Chizitem) Ibeneme
Purpose : Read-only monitoring and log-analysis operations for the OSSEC HIDS
          lab and the Gophish phishing-simulation lab. These are the
          OBSERVE-only operations — tailing and searching OSSEC alerts, Apache
          error logs, system auth logs, and syslog. Nothing here changes system
          state. (State-changing provisioning lives in lab_mgmt.py.)

Scope   : Blue-team detection and diagnosis. Used to:
            - Watch OSSEC alerts.log live during attack simulation to confirm
              detection of Windows user-creation (Event 4720 -> Rule 18101 L8),
              privilege changes (4732), and RDP enablement (service-state 7040).
            - Diagnose the PHP 8 blank-WUI page via the Apache error log.
            - Identify the AppArmor denial flood (Rule 52002) in syslog.
            - Monitor Gophish stdout for SMTP/ngrok/campaign events.

Design  : Each analysis task is a subcommand wrapping the underlying log tool
          (tail/grep/etc.). A --dry-run flag prints the command instead of
          running it, so the toolkit reads cleanly and is safe to demonstrate
          on a host without the log files present.

Usage   : python3 lab_monitoring.py --help
          python3 lab_monitoring.py alerts-follow
          python3 lab_monitoring.py alerts-rule 18101
          python3 lab_monitoring.py top-rules
          python3 lab_monitoring.py apache-php-errors

Requires: Python 3.8+, standard GNU utilities (tail, grep, awk, less, zcat).
=============================================================================
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from dataclasses import dataclass


# =============================================================================
# PATHS — canonical log locations used across both labs
# =============================================================================

ALERTS_LOG = "/var/ossec/logs/alerts/alerts.log"
ALERTS_DIR = "/var/ossec/logs/alerts/"
OSSEC_LOG = "/var/ossec/logs/ossec.log"
ACTIVE_RESPONSE_LOG = "/var/ossec/logs/active-responses.log"
APACHE_ERROR_LOG = "/var/log/apache2/error.log"
APACHE_ACCESS_LOG = "/var/log/apache2/access.log"
AUTH_LOG = "/var/log/auth.log"
SYSLOG = "/var/log/syslog"


# =============================================================================
# CORE HELPER
# =============================================================================

@dataclass
class RunResult:
    command: str
    returncode: int


def run(command: str, *, dry_run: bool = False) -> RunResult:
    """Run a read-only log command, or print it under --dry-run.

    Streaming commands (tail -f, less) run in the foreground so the operator
    can watch or scroll; Ctrl+C returns control.
    """
    prefix = "[DRY-RUN] " if dry_run else "[RUN] "
    print(f"{prefix}{command}")
    if dry_run:
        return RunResult(command, 0)
    proc = subprocess.run(command, shell=True, text=True)
    return RunResult(command, proc.returncode)


# =============================================================================
# OSSEC ALERT LOG  (from ossec-management.sh + log-monitoring.sh)
# The primary output of the detection engine: one alert block per event with
# rule ID, level, and the raw log line that triggered it.
# =============================================================================

def alerts_follow(dry_run: bool = False) -> None:
    """Follow the live OSSEC alert stream (tail -f).

    This is the command used during attack simulation to watch detections fire
    in real time as the Meterpreter post-exploitation activity ran on the agent.
    """
    run(f"sudo tail -f {ALERTS_LOG}", dry_run=dry_run)


def alerts_tail(lines: int = 50, dry_run: bool = False) -> None:
    """Show the last N OSSEC alert entries."""
    run(f"sudo tail -{int(lines)} {ALERTS_LOG}", dry_run=dry_run)


def alerts_by_rule(rule_id: str, dry_run: bool = False) -> None:
    """Search alerts for a specific rule ID (e.g. 18101 = Windows account events)."""
    run(f"sudo grep 'Rule: {shlex.quote(rule_id)}' {ALERTS_LOG}", dry_run=dry_run)


def alerts_by_event(event_id: str, context: bool = True,
                    dry_run: bool = False) -> None:
    """Search alerts for a Windows Event ID (e.g. 4720 = user account created).

    With context, shows surrounding lines so the full alert block is readable.
    Key lab events: 4720 (user created), 4732 (added to admin group),
    7040 (service startup mode changed — RDP enablement).
    """
    if context:
        run(f"sudo grep -B2 -A5 {shlex.quote(event_id)} {ALERTS_LOG}",
            dry_run=dry_run)
    else:
        run(f"sudo grep {shlex.quote(event_id)} {ALERTS_LOG}", dry_run=dry_run)


def alerts_high_severity(dry_run: bool = False) -> None:
    """Show high-severity alerts (level 7 and above)."""
    run(f"sudo grep 'level [789]' {ALERTS_LOG}", dry_run=dry_run)


def alerts_windows(dry_run: bool = False) -> None:
    """Show all Windows Event Log (WinEvtLog) alerts."""
    run(f"sudo grep 'WinEvtLog' {ALERTS_LOG}", dry_run=dry_run)


def alerts_search(term: str, ignore_case: bool = True,
                  dry_run: bool = False) -> None:
    """Free-text search across the alert log (e.g. a backdoor account name)."""
    flag = "-i " if ignore_case else ""
    run(f"sudo grep {flag}{shlex.quote(term)} {ALERTS_LOG}", dry_run=dry_run)


def top_rules(limit: int = 10, dry_run: bool = False) -> None:
    """Rank the most frequently triggered rules — a fast triage view.

    Useful for spotting noise (e.g. the Rule 52002 AppArmor-denial flood) vs.
    the genuine attack detections underneath it.
    """
    cmd = (f"sudo grep 'Rule:' {ALERTS_LOG} | "
           f"grep -o 'Rule: [0-9]*' | sort | uniq -c | sort -rn | "
           f"head -{int(limit)}")
    run(cmd, dry_run=dry_run)


def alerts_for_date(date_str: str, dry_run: bool = False) -> None:
    """View archived alerts for a date (e.g. 2026-Mar-28). Lists the dir first."""
    run(f"ls {ALERTS_DIR}", dry_run=dry_run)
    run(f"sudo cat {ALERTS_DIR}ossec-alerts-{shlex.quote(date_str)}.log",
        dry_run=dry_run)


# =============================================================================
# OSSEC OPERATIONAL LOG — daemon health, not detections
# =============================================================================

def ossec_log_errors(dry_run: bool = False) -> None:
    """Grep the OSSEC operational log for errors (e.g. a daemon failing to start)."""
    run(f"sudo grep -i 'error' {OSSEC_LOG}", dry_run=dry_run)


def ossec_log_remoted(dry_run: bool = False) -> None:
    """Check remoted (agent-communication daemon) messages in the OSSEC log."""
    run(f"sudo grep -i 'remoted' {OSSEC_LOG}", dry_run=dry_run)


def active_responses(dry_run: bool = False) -> None:
    """Show what OSSEC actively responded to (e.g. firewall blocks)."""
    run(f"sudo cat {ACTIVE_RESPONSE_LOG}", dry_run=dry_run)


# =============================================================================
# APACHE LOGS  (from apache-and-php.sh + log-monitoring.sh)
# =============================================================================

def apache_error_tail(lines: int = 30, follow: bool = False,
                       dry_run: bool = False) -> None:
    """View (or follow) the Apache error log — how the blank-WUI bug was found."""
    if follow:
        run(f"sudo tail -f {APACHE_ERROR_LOG}", dry_run=dry_run)
    else:
        run(f"sudo tail -{int(lines)} {APACHE_ERROR_LOG}", dry_run=dry_run)


def apache_php_errors(dry_run: bool = False) -> None:
    """Isolate PHP fatal errors in the Apache log.

    Surfaces the specific 'curly braces no longer supported' fatal that the
    PHP-8-incompatible OSSEC WUI produced before the downgrade to PHP 7.4.
    """
    run(f"sudo grep 'PHP Fatal' {APACHE_ERROR_LOG}", dry_run=dry_run)
    run(f"sudo grep 'curly braces' {APACHE_ERROR_LOG}", dry_run=dry_run)


def apache_access_follow(dry_run: bool = False) -> None:
    """Follow the Apache access log to confirm requests are reaching the server."""
    run(f"sudo tail -f {APACHE_ACCESS_LOG}", dry_run=dry_run)


# =============================================================================
# AUTH LOG — logins, sudo, SSH
# =============================================================================

def auth_failed_logins(dry_run: bool = False) -> None:
    """Search for failed password attempts (basic brute-force signal)."""
    run(f"sudo grep 'Failed password' {AUTH_LOG}", dry_run=dry_run)


def auth_sudo(dry_run: bool = False) -> None:
    """Search for sudo usage in the auth log."""
    run(f"sudo grep 'sudo' {AUTH_LOG}", dry_run=dry_run)


def auth_ssh(dry_run: bool = False) -> None:
    """Search for SSH (sshd) events in the auth log."""
    run(f"sudo grep 'sshd' {AUTH_LOG}", dry_run=dry_run)


def auth_follow(dry_run: bool = False) -> None:
    """Follow the auth log live (logon/logoff/sudo monitoring)."""
    run(f"sudo tail -f {AUTH_LOG}", dry_run=dry_run)


# =============================================================================
# SYSLOG — general events, including the AppArmor denial flood
# =============================================================================

def syslog_apparmor(dry_run: bool = False) -> None:
    """Show recent AppArmor denials in syslog.

    These Firefox snap-profile denials (/proc/pressure/memory) were what OSSEC
    logged as the Rule 52002 flood that buried real detections in the WUI.
    """
    run(f"sudo grep -i 'apparmor' {SYSLOG} | tail -20", dry_run=dry_run)


def syslog_apparmor_counts(dry_run: bool = False) -> None:
    """Count AppArmor denials per profile — quantifies the noise source."""
    cmd = (f"sudo grep 'apparmor=\"DENIED\"' {SYSLOG} | "
           f"grep -o 'profile=\"[^\"]*\"' | sort | uniq -c | sort -rn")
    run(cmd, dry_run=dry_run)


def syslog_follow(dry_run: bool = False) -> None:
    """Follow syslog live."""
    run(f"sudo tail -f {SYSLOG}", dry_run=dry_run)


def syslog_compressed_apparmor(dry_run: bool = False) -> None:
    """Search a rotated/compressed syslog (.gz) without extracting it."""
    run("sudo zcat /var/log/syslog.2.gz | grep 'apparmor'", dry_run=dry_run)


# =============================================================================
# GOPHISH MONITORING  (from gophish-infrastructure.sh + log-monitoring.sh)
# =============================================================================

def gophish_log_follow(dry_run: bool = False) -> None:
    """Follow the Gophish stdout log (SMTP delivery, ngrok status, events)."""
    run("tail -f gophish.log", dry_run=dry_run)


def gophish_results(dry_run: bool = False) -> None:
    """Query the Gophish SQLite DB for campaign results and recent events."""
    run("sqlite3 gophish.db 'SELECT * FROM results;'", dry_run=dry_run)
    run("sqlite3 gophish.db "
        "'SELECT * FROM events ORDER BY time DESC LIMIT 20;'", dry_run=dry_run)


def ngrok_status(dry_run: bool = False) -> None:
    """Print the current ngrok public URL via its local API."""
    cmd = ("curl -s http://127.0.0.1:4040/api/tunnels | "
           "python3 -c \"import sys,json; "
           "print(json.load(sys.stdin)['tunnels'][0]['public_url'])\"")
    run(cmd, dry_run=dry_run)


# =============================================================================
# CLI
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lab_monitoring.py",
        description="Read-only monitoring/log-analysis toolkit for the OSSEC "
                    "HIDS and Gophish labs.",
    )
    p.add_argument("--dry-run", action="store_true",
                   help="print commands without executing them")
    sub = p.add_subparsers(dest="cmd", required=True)

    # OSSEC alerts
    sub.add_parser("alerts-follow", help="tail -f the live alert stream")
    sp = sub.add_parser("alerts-tail", help="last N alerts")
    sp.add_argument("--lines", type=int, default=50)
    sp = sub.add_parser("alerts-rule", help="alerts for a rule ID")
    sp.add_argument("rule_id")
    sp = sub.add_parser("alerts-event", help="alerts for a Windows Event ID")
    sp.add_argument("event_id")
    sp.add_argument("--no-context", action="store_true")
    sub.add_parser("alerts-high", help="level 7+ alerts")
    sub.add_parser("alerts-windows", help="all WinEvtLog alerts")
    sp = sub.add_parser("alerts-search", help="free-text alert search")
    sp.add_argument("term")
    sp.add_argument("--case-sensitive", action="store_true")
    sp = sub.add_parser("top-rules", help="most frequently triggered rules")
    sp.add_argument("--limit", type=int, default=10)
    sp = sub.add_parser("alerts-date", help="archived alerts for a date")
    sp.add_argument("date_str", help="e.g. 2026-Mar-28")

    # OSSEC operational
    sub.add_parser("ossec-errors", help="errors in the OSSEC operational log")
    sub.add_parser("ossec-remoted", help="remoted messages")
    sub.add_parser("active-responses", help="active-response actions taken")

    # Apache
    sp = sub.add_parser("apache-error", help="view/follow Apache error log")
    sp.add_argument("--lines", type=int, default=30)
    sp.add_argument("--follow", action="store_true")
    sub.add_parser("apache-php-errors", help="isolate PHP fatal errors")
    sub.add_parser("apache-access", help="follow the Apache access log")

    # auth
    sub.add_parser("auth-failed", help="failed password attempts")
    sub.add_parser("auth-sudo", help="sudo usage")
    sub.add_parser("auth-ssh", help="sshd events")
    sub.add_parser("auth-follow", help="follow the auth log")

    # syslog
    sub.add_parser("syslog-apparmor", help="recent AppArmor denials")
    sub.add_parser("syslog-apparmor-counts", help="denials per profile")
    sub.add_parser("syslog-follow", help="follow syslog")
    sub.add_parser("syslog-apparmor-gz", help="search rotated .gz syslog")

    # gophish
    sub.add_parser("gophish-log", help="follow Gophish stdout log")
    sub.add_parser("gophish-results", help="query campaign results DB")
    sub.add_parser("ngrok-status", help="print current ngrok public URL")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    d = args.dry_run

    dispatch = {
        "alerts-follow": lambda: alerts_follow(d),
        "alerts-tail": lambda: alerts_tail(args.lines, d),
        "alerts-rule": lambda: alerts_by_rule(args.rule_id, d),
        "alerts-event": lambda: alerts_by_event(
            args.event_id, not args.no_context, d),
        "alerts-high": lambda: alerts_high_severity(d),
        "alerts-windows": lambda: alerts_windows(d),
        "alerts-search": lambda: alerts_search(
            args.term, not args.case_sensitive, d),
        "top-rules": lambda: top_rules(args.limit, d),
        "alerts-date": lambda: alerts_for_date(args.date_str, d),
        "ossec-errors": lambda: ossec_log_errors(d),
        "ossec-remoted": lambda: ossec_log_remoted(d),
        "active-responses": lambda: active_responses(d),
        "apache-error": lambda: apache_error_tail(args.lines, args.follow, d),
        "apache-php-errors": lambda: apache_php_errors(d),
        "apache-access": lambda: apache_access_follow(d),
        "auth-failed": lambda: auth_failed_logins(d),
        "auth-sudo": lambda: auth_sudo(d),
        "auth-ssh": lambda: auth_ssh(d),
        "auth-follow": lambda: auth_follow(d),
        "syslog-apparmor": lambda: syslog_apparmor(d),
        "syslog-apparmor-counts": lambda: syslog_apparmor_counts(d),
        "syslog-follow": lambda: syslog_follow(d),
        "syslog-apparmor-gz": lambda: syslog_compressed_apparmor(d),
        "gophish-log": lambda: gophish_log_follow(d),
        "gophish-results": lambda: gophish_results(d),
        "ngrok-status": lambda: ngrok_status(d),
    }

    try:
        dispatch[args.cmd]()
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
