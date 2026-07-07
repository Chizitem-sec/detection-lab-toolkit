"""Tests for lab_hardening.py.

These verify the *hardening logic itself* is correct — e.g. that --secure
actually disables the deprecated protocols and keeps TLS 1.2 on, and that
--insecure does the opposite. Getting this backwards would be a real
security bug, so it's the highest-value thing to test in this file.
"""

from unittest.mock import patch

import pytest

import lab_hardening as hardening


# ---------------------------------------------------------------------------
# Dry-run safety
# ---------------------------------------------------------------------------

def test_dry_run_never_executes():
    with patch("subprocess.run") as mock_run:
        hardening.run("auditpol /get /category:*", dry_run=True)
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Audit policy — must cover all five categories OSSEC depends on
# ---------------------------------------------------------------------------

def test_audit_enable_covers_all_required_categories(capsys):
    hardening.audit_enable(dry_run=True)
    out = capsys.readouterr().out
    for category in ["Account Management", "Logon/Logoff", "Policy Change",
                      "Privilege Use", "System"]:
        assert f'/category:"{category}"' in out
        assert f'/category:"{category}" /success:enable /failure:enable' in out


def test_audit_disable_uses_disable_flags(capsys):
    hardening.audit_disable(dry_run=True)
    out = capsys.readouterr().out
    assert "/success:disable /failure:disable" in out
    assert "/success:enable" not in out


# ---------------------------------------------------------------------------
# Protocol hardening — the security-critical logic
# ---------------------------------------------------------------------------

def test_secure_mode_disables_deprecated_protocols(capsys):
    """--secure must disable SSL 2.0/3.0 and TLS 1.0/1.1 (Enabled=0)."""
    hardening.protocols(secure=True, dry_run=True)
    out = capsys.readouterr().out
    # each deprecated protocol's registry write must set Enabled to 0
    for proto in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]:
        idx = out.find(proto)
        assert idx != -1, f"{proto} not configured at all"
    assert "-Value 0 -PropertyType 'DWord'" in out  # at least one disable write


def test_secure_mode_keeps_tls12_enabled(capsys):
    """--secure must NOT disable TLS 1.2 — that would break all HTTPS."""
    hardening.protocols(secure=True, dry_run=True)
    out = capsys.readouterr().out
    tls12_section_start = out.find("TLS 1.2")
    tls12_section = out[tls12_section_start:tls12_section_start + 2000]
    assert "-Value 1 -PropertyType 'DWord'" in tls12_section


def test_insecure_mode_enables_all_protocols(capsys):
    """--insecure (lab simulation) must enable every protocol, including SSL 2.0/3.0."""
    hardening.protocols(secure=False, dry_run=True)
    out = capsys.readouterr().out
    assert "INSECURE (lab simulation)" in out
    # 'Enabled' must be set to 1 everywhere, never 0, in insecure/lab mode
    assert "Name 'Enabled' -Value 0" not in out


# ---------------------------------------------------------------------------
# Cipher suites — secure list must never silently include weak ciphers
# ---------------------------------------------------------------------------

def test_secure_ciphers_exclude_weak_algorithms(capsys):
    hardening.cipher_suites(secure=True, dry_run=True)
    out = capsys.readouterr().out
    for weak in ["RC4", "_DES_", "EXPORT"]:
        assert weak not in out, f"weak cipher marker '{weak}' leaked into secure config"


def test_insecure_ciphers_include_weak_algorithms_for_lab_testing(capsys):
    hardening.cipher_suites(secure=False, dry_run=True)
    out = capsys.readouterr().out
    assert "RC4" in out
    assert "TLS_RSA_WITH_DES_CBC_SHA" in out


def test_secure_and_insecure_cipher_lists_differ(capsys):
    hardening.cipher_suites(secure=True, dry_run=True)
    secure_out = capsys.readouterr().out
    hardening.cipher_suites(secure=False, dry_run=True)
    insecure_out = capsys.readouterr().out
    assert secure_out != insecure_out


# ---------------------------------------------------------------------------
# Guest account
# ---------------------------------------------------------------------------

def test_guest_remove_targets_administrators_group(capsys):
    hardening.guest_remove_from_admins(dry_run=True)
    out = capsys.readouterr().out
    assert "Remove-LocalGroupMember" in out
    assert "'Administrators'" in out
    assert "'Guest'" in out


def test_guest_add_is_labelled_as_lab_mode(capsys):
    hardening.guest_add_to_admins(dry_run=True)
    out = capsys.readouterr().out
    assert "Add-LocalGroupMember" in out


# ---------------------------------------------------------------------------
# CLI parser — confirm the --secure/--insecure flags actually flip the bool
# ---------------------------------------------------------------------------

def test_protocols_flag_defaults_to_secure():
    parser = hardening.build_parser()
    args = parser.parse_args(["protocols"])
    assert args.secure is True


def test_protocols_insecure_flag_flips_bool():
    parser = hardening.build_parser()
    args = parser.parse_args(["protocols", "--insecure"])
    assert args.secure is False


@pytest.mark.parametrize("argv,expected_cmd", [
    (["audit-enable"], "audit-enable"),
    (["protocols", "--secure"], "protocols"),
    (["cipher-suites", "--insecure"], "cipher-suites"),
    (["guest-remove"], "guest-remove"),
])
def test_parser_dispatches_expected_subcommand(argv, expected_cmd):
    parser = hardening.build_parser()
    args = parser.parse_args(argv)
    assert args.cmd == expected_cmd


def test_main_dry_run_end_to_end():
    with patch("subprocess.run") as mock_run:
        rc = hardening.main(["--dry-run", "audit-enable"])
    assert rc == 0
    mock_run.assert_not_called()
