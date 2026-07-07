"""Tests for lab_mgmt.py.

These tests exercise dry-run mode exclusively: they verify the *shape* of
the commands each function would run (correct binaries, correct ordering,
correct arguments) without ever touching a real system. subprocess.run is
also mocked and asserted as never called under --dry-run, which is the
safety guarantee the whole toolkit depends on.
"""

from unittest.mock import patch

import pytest

import lab_mgmt as mgmt


# ---------------------------------------------------------------------------
# run() / run_all() core helper
# ---------------------------------------------------------------------------

def test_dry_run_never_calls_subprocess():
    """The single most important guarantee: --dry-run must not execute anything."""
    with patch("subprocess.run") as mock_run:
        mgmt.run("sudo rm -rf /", dry_run=True)
        mock_run.assert_not_called()


def test_run_executes_when_not_dry_run():
    """Sanity check the opposite path: without dry_run, subprocess.run IS called."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        mgmt.run("echo hello", dry_run=False)
        mock_run.assert_called_once()


def test_run_all_stops_on_failure(capsys):
    """run_all should stop after the first non-zero exit code."""
    with patch("subprocess.run") as mock_run:
        # first command succeeds, second fails
        mock_run.side_effect = [
            type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
            type("P", (), {"returncode": 1, "stdout": "", "stderr": ""})(),
        ]
        mgmt.run_all(["cmd-one", "cmd-two", "cmd-three"], dry_run=False)
    out = capsys.readouterr()
    assert "cmd-one" in out.out
    assert "cmd-two" in out.out
    assert "cmd-three" not in out.out  # never reached — stopped after cmd-two failed


# ---------------------------------------------------------------------------
# Apache / PHP procedures
# ---------------------------------------------------------------------------

def test_apache_switch_php_command_order(capsys):
    """Switching PHP versions must dismod the old version before enmod'ing the new one."""
    mgmt.apache_switch_php("8.3", "7.4", dry_run=True)
    out = capsys.readouterr().out
    dismod_pos = out.find("a2dismod php8.3")
    enmod_pos = out.find("a2enmod php7.4")
    restart_pos = out.find("systemctl restart apache2")
    assert dismod_pos != -1 and enmod_pos != -1 and restart_pos != -1
    assert dismod_pos < enmod_pos < restart_pos


def test_deploy_ossec_wui_fixes_permissions_after_clone(capsys):
    """WUI deployment must chown/chmod AFTER moving the repo into the web root."""
    mgmt.deploy_ossec_wui(dry_run=True)
    out = capsys.readouterr().out
    assert out.find("git clone") < out.find("chown -R www-data")
    assert "chmod -R 755" in out


# ---------------------------------------------------------------------------
# Service control validation
# ---------------------------------------------------------------------------

def test_service_rejects_invalid_action():
    with pytest.raises(ValueError):
        mgmt.service("launch-nukes", "apache2", dry_run=True)


def test_service_accepts_valid_action(capsys):
    mgmt.service("restart", "apache2", dry_run=True)
    out = capsys.readouterr().out
    assert "systemctl restart apache2" in out


def test_ossec_rejects_invalid_action():
    with pytest.raises(ValueError):
        mgmt.ossec("reboot-the-universe", dry_run=True)


# ---------------------------------------------------------------------------
# Shell-safety: arguments must be quoted, not interpolated raw
# ---------------------------------------------------------------------------

def test_apparmor_complain_quotes_profile_path(capsys):
    """A profile path with a space must come out safely quoted."""
    mgmt.apparmor_complain("/some path/with space", dry_run=True)
    out = capsys.readouterr().out
    assert "'/some path/with space'" in out


def test_serve_directory_quotes_path(capsys):
    mgmt.serve_directory("/tmp/needs quoting", port=9090, dry_run=True)
    out = capsys.readouterr().out
    assert "9090" in out
    assert "'/tmp/needs quoting'" in out


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

def test_parser_builds_without_error():
    parser = mgmt.build_parser()
    assert parser is not None


@pytest.mark.parametrize("argv,expected_cmd", [
    (["service", "restart", "apache2"], "service"),
    (["ossec", "status"], "ossec"),
    (["apache-switch-php", "--from", "8.3", "--to", "7.4"], "apache-switch-php"),
    (["ossec-list-agents"], "ossec-list-agents"),
    (["gophish-build"], "gophish-build"),
])
def test_parser_dispatches_expected_subcommand(argv, expected_cmd):
    parser = mgmt.build_parser()
    args = parser.parse_args(argv)
    assert args.cmd == expected_cmd


def test_main_dry_run_end_to_end():
    """Full main() invocation in dry-run mode should exit 0 and touch no system state."""
    with patch("subprocess.run") as mock_run:
        rc = mgmt.main(["--dry-run", "service", "restart", "apache2"])
    assert rc == 0
    mock_run.assert_not_called()


def test_main_rejects_invalid_service_action_via_argparse():
    """argparse itself rejects an invalid 'choices' value with SystemExit(2),
    before main()'s try/except (which handles ValueError/RuntimeError from
    inside the dispatched function) ever runs."""
    with pytest.raises(SystemExit) as exc_info:
        mgmt.main(["--dry-run", "service", "notarealaction", "apache2"])
    assert exc_info.value.code == 2
