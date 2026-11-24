"""Regression tests for npm/pnpm builds and their audit.

Run: uv run --with pytest pytest tests
"""

import importlib
import json
import os
import types

import pytest
from click.testing import CliRunner

NPM_REPORT = {
    "vulnerabilities": {},
    "metadata": {
        "vulnerabilities": {"info": 0, "low": 1, "moderate": 2, "high": 0, "critical": 0, "total": 3},
        "dependencies": {"total": 50},
    },
}
# pnpm: no "total", dependencies as plain number
PNPM_REPORT = {
    "advisories": {},
    "metadata": {
        "vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 1, "critical": 1},
        "dependencies": 77,
    },
}
CLEAN_PNPM_REPORT = {
    "advisories": {},
    "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0}, "dependencies": 5},
}


@pytest.fixture
def mods(tmp_path, monkeypatch):
    # viur_cli.conf writes config files into the cwd on import - keep them out of the repo.
    monkeypatch.chdir(tmp_path)
    return types.SimpleNamespace(
        build=importlib.import_module("viur_cli.build"),
        local=importlib.import_module("viur_cli.local"),
        utils=importlib.import_module("viur_cli.utils"),
    )


def _profile(builds):
    return {"sources_folder": "./sources", "distribution_folder": "./deploy", "builds": builds}


def _use_profiles(monkeypatch, local, get_profile):
    # config is None outside a viur project, so replace the whole object.
    monkeypatch.setattr(local, "config", types.SimpleNamespace(get_profile=get_profile))


def _fake_audit(monkeypatch, local, reports, which=lambda tool: True):
    """Patch subprocess.run: pip-audit is clean, npm/pnpm return the given report (dict or raw str)."""
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs.get("cwd")))
        if cmd[0] == "uvx":
            stdout = json.dumps({"dependencies": []})
        else:
            report = reports[cmd[0]]
            stdout = report if isinstance(report, str) else json.dumps(report)
        return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(local.subprocess, "run", run)
    monkeypatch.setattr(local.shutil, "which", which)
    return calls


def test_build_pnpm_runs_pnpm_in_quoted_source(mods, monkeypatch):
    cmds = []
    monkeypatch.setattr(mods.utils, "system", cmds.append)

    mods.build._build(_profile({}), "fe", {"kind": "pnpm", "source": "my app", "command": "build"}, ())
    mods.build._build(_profile({}), "fe", {"kind": "npm", "source": "fe", "command": "build"}, ())

    assert cmds == [
        "cd './sources/my app' && pnpm install && pnpm run build",
        "cd ./sources/fe && npm install && npm run build",
    ]


def test_clean_pnpm_drops_target_and_node_modules(mods, monkeypatch):
    removed = []
    monkeypatch.setattr(mods.utils, "rmdir", removed.append)

    mods.build._clean(_profile({}), "fe", {"kind": "pnpm", "source": "fe", "target": "fe"})

    assert removed == [os.path.join("./deploy", "fe"), os.path.join("./sources", "fe", "node_modules")]


def test_rmdir_refuses_symlink_out_of_project(mods, tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    (outside / "node_modules").mkdir(parents=True)
    (tmp_path / "sources").symlink_to(outside)

    with pytest.raises(SystemExit):
        mods.utils.rmdir("sources/node_modules")

    assert (outside / "node_modules").exists()


def test_audit_reads_npm_and_pnpm_reports(mods, monkeypatch, capsys):
    _use_profiles(monkeypatch, mods.local, lambda p: _profile({
        "a": {"kind": "npm", "source": "a"},
        "b": {"kind": "pnpm", "source": "b"},
        "c": {"kind": "exec", "command": "true"},
    }))
    calls = _fake_audit(monkeypatch, mods.local, {"npm": NPM_REPORT, "pnpm": PNPM_REPORT})

    assert mods.local.do_checks(dev=False) is False

    assert (["npm", "audit", "--json"], "./sources/a") in calls
    assert (["pnpm", "audit", "--json"], "./sources/b") in calls
    out = capsys.readouterr().out
    assert "Total Dependencies:     77" in out
    assert "Total Vulnerabilities:  2" in out


def test_audit_clean_pnpm_passes(mods, monkeypatch):
    _use_profiles(monkeypatch, mods.local, lambda p: _profile({"b": {"kind": "pnpm", "source": "b"}}))
    _fake_audit(monkeypatch, mods.local, {"pnpm": CLEAN_PNPM_REPORT})

    assert mods.local.do_checks(dev=False) is True


@pytest.mark.parametrize("report, which", [
    (CLEAN_PNPM_REPORT, lambda tool: False),  # pnpm not installed
    ({"error": {"code": "ERR_PNPM_AUDIT_BAD_RESPONSE"}}, lambda tool: True),  # registry error
    ("not json", lambda tool: True),  # broken report
])
def test_audit_failure_fails_check(mods, monkeypatch, report, which):
    _use_profiles(monkeypatch, mods.local, lambda p: _profile({"b": {"kind": "pnpm", "source": "b"}}))
    _fake_audit(monkeypatch, mods.local, {"pnpm": report}, which=which)

    assert mods.local.do_checks(dev=False) is False


def test_audit_uses_given_profile(mods, monkeypatch):
    profiles = {
        "default": _profile({}),
        "live": _profile({"b": {"kind": "pnpm", "source": "b"}}),
    }
    _use_profiles(monkeypatch, mods.local, profiles.__getitem__)
    _fake_audit(monkeypatch, mods.local, {"pnpm": PNPM_REPORT})

    assert mods.local.do_checks(dev=False) is True
    assert mods.local.do_checks(dev=False, profile="live") is False


def test_check_exit_code(mods, monkeypatch):
    _use_profiles(monkeypatch, mods.local, lambda p: _profile({"b": {"kind": "pnpm", "source": "b"}}))
    reports = {"pnpm": PNPM_REPORT}
    _fake_audit(monkeypatch, mods.local, reports)

    assert CliRunner().invoke(mods.local.check, []).exit_code == 1

    reports["pnpm"] = CLEAN_PNPM_REPORT
    assert CliRunner().invoke(mods.local.check, []).exit_code == 0
