"""Tests for lab_monitoring.py.

All commands here are read-only by design (tail/grep/cat/sqlite3 queries),
but we still verify under --dry-run that nothing is executed, and that the
generated commands target the correct log paths and use safe quoting for
user-supplied search terms.
"""

from unittest.mock import patch

import pytest

import lab_monitoring as mon


# ---------------------------------------------------------------------------
# Dry-run safety
# ---------------------------------------------------------------------------

def test_dry_run_never_executes():
    with patch("subprocess.run") as mock_run:
        mon.run("tail -f /var/ossec/logs/alerts/alerts.log", dry_run=True)
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Correct log paths targeted
# ---------------------------------------------------------------------------

def test_alerts_follow_targets_correct_log(capsys):
    mon.alerts_follow(dry_run=True)
    out = capsys.readouterr().out
    assert mon.ALERTS_LOG in out
    assert "tail -f" in out


def test_alerts_by_rule_targets_correct_log(capsys):
    mon.alerts_by_rule("18101", dry_run=True)
    out = capsys.readouterr().out
    assert "Rule: 18101" in out
    assert mon.ALERTS_LOG in out


def test_apache_php_errors_checks_both_signatures(capsys):
    """This diagnosed the real PHP-8 blank-WUI bug — must check both error strings."""
    mon.apache_php_errors(dry_run=True)
    out = capsys.readouterr().out
    assert "PHP Fatal" in out
    assert "curly braces" in out
    assert mon.APACHE_ERROR_LOG in out


def test_syslog_apparmor_counts_pipeline_order(capsys):
    """The AppArmor-noise ranking pipeline must grep, extract, then sort/count."""
    mon.syslog_apparmor_counts(dry_run=True)
    out = capsys.readouterr().out
    assert out.find("grep") < out.find("sort") < out.find("uniq -c")


def test_top_rules_respects_limit(capsys):
    mon.top_rules(limit=3, dry_run=True)
    out = capsys.readouterr().out
    assert "head -3" in out


# ---------------------------------------------------------------------------
# Safe quoting of user-supplied search terms
# ---------------------------------------------------------------------------

def test_alerts_search_quotes_term_with_special_chars(capsys):
    mon.alerts_search("hacked; rm -rf /", dry_run=True)
    out = capsys.readouterr().out
    # The dangerous term must be shell-quoted as a single token, not
    # left able to break out into a second command.
    assert "'hacked; rm -rf /'" in out


def test_alerts_by_event_context_flag(capsys):
    mon.alerts_by_event("4720", context=True, dry_run=True)
    out = capsys.readouterr().out
    assert "-B2 -A5" in out

    mon.alerts_by_event("4720", context=False, dry_run=True)
    out2 = capsys.readouterr().out
    assert "-B2 -A5" not in out2


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv,expected_cmd", [
    (["alerts-follow"], "alerts-follow"),
    (["alerts-rule", "18101"], "alerts-rule"),
    (["alerts-event", "4720"], "alerts-event"),
    (["top-rules", "--limit", "5"], "top-rules"),
    (["gophish-results"], "gophish-results"),
])
def test_parser_dispatches_expected_subcommand(argv, expected_cmd):
    parser = mon.build_parser()
    args = parser.parse_args(argv)
    assert args.cmd == expected_cmd


def test_main_dry_run_end_to_end():
    with patch("subprocess.run") as mock_run:
        rc = mon.main(["--dry-run", "alerts-rule", "18101"])
    assert rc == 0
    mock_run.assert_not_called()
