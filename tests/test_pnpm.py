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


def _fake_audit(monkeypatch, local, reports, which=lambda tool: True, returncode=None):
    """Patch subprocess.run: pip-audit is clean, npm/pnpm return the given report (dict or raw str).

    Like the real tools, the audit exits 1 when it reports vulnerabilities,
    unless ``returncode`` forces a value.
    """
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs.get("cwd")))
        if cmd[0] == "uvx":
            return types.SimpleNamespace(returncode=0, stdout=json.dumps({"dependencies": []}), stderr="")
        report = reports[cmd[0]]
        if isinstance(report, str):
            return types.SimpleNamespace(returncode=returncode or 1, stdout=report, stderr="")
        counts = report.get("metadata", {}).get("vulnerabilities", {})
        found = any(v for k, v in counts.items() if k != "total")
        code = returncode if returncode is not None else int(found)
        return types.SimpleNamespace(returncode=code, stdout=json.dumps(report), stderr="")

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


def test_rmdir_refuses_symlink_as_last_component(mods, tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-linked"
    (outside / "keep").mkdir(parents=True)
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "fe").symlink_to(outside)

    with pytest.raises(SystemExit):
        mods.utils.rmdir("deploy/fe")

    assert (outside / "keep").exists()


def test_rmdir_refuses_symlink_into_project(mods, tmp_path):
    # e.g. a build target linked to the sources: the link target must survive
    (tmp_path / "sources" / "keep").mkdir(parents=True)
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "fe").symlink_to(tmp_path / "sources")

    with pytest.raises(SystemExit):
        mods.utils.rmdir("deploy/fe")

    assert (tmp_path / "sources" / "keep").exists()


@pytest.mark.parametrize("path", [".", "./", "deploy/.."])
def test_rmdir_refuses_project_root(mods, tmp_path, path):
    (tmp_path / "deploy").mkdir()

    with pytest.raises(SystemExit):
        mods.utils.rmdir(path)

    assert (tmp_path / "deploy").exists()


def test_rmdir_removes_folder_inside_project(mods, tmp_path):
    (tmp_path / "sources" / "fe" / "node_modules" / "x").mkdir(parents=True)

    mods.utils.rmdir("sources/fe/node_modules")
    mods.utils.rmdir("sources/fe/missing")  # missing folders are ignored

    assert not (tmp_path / "sources" / "fe" / "node_modules").exists()


def test_rmdir_refuses_symlink_out_of_project(mods, tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    (outside / "node_modules").mkdir(parents=True)
    (tmp_path / "sources").symlink_to(outside)

    with pytest.raises(SystemExit):
        mods.utils.rmdir("sources/node_modules")

    assert (outside / "node_modules").exists()


def test_audit_without_project_runs_python_only(mods, monkeypatch):
    monkeypatch.setattr(mods.local, "config", None)
    calls = _fake_audit(monkeypatch, mods.local, {}, which=lambda tool: False)

    assert mods.local.do_checks(dev=False) is True
    assert [c[0][0] for c in calls] == ["uvx"]


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


@pytest.mark.parametrize("report, which, returncode", [
    (CLEAN_PNPM_REPORT, lambda tool: False, None),  # pnpm not installed
    ({"error": {"code": "ERR_PNPM_AUDIT_BAD_RESPONSE"}}, lambda tool: True, 1),  # registry error
    ("not json", lambda tool: True, 1),  # broken report
    ({"metadata": {}}, lambda tool: True, 1),  # report without counts
    ({"metadata": {}}, lambda tool: True, 0),  # ... even with exit 0
    (CLEAN_PNPM_REPORT, lambda tool: True, 1),  # tool failed, nothing found
])
def test_audit_failure_fails_check(mods, monkeypatch, report, which, returncode):
    _use_profiles(monkeypatch, mods.local, lambda p: _profile({"b": {"kind": "pnpm", "source": "b"}}))
    _fake_audit(monkeypatch, mods.local, {"pnpm": report}, which=which, returncode=returncode)

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


def test_declined_deploy_aborts_without_gcloud(mods, monkeypatch):
    cloud = importlib.import_module("viur_cli.cloud")
    calls = []
    monkeypatch.setattr(cloud, "config", types.SimpleNamespace(get_profile=lambda p: {"version": "v"}))
    monkeypatch.setattr(mods.local, "do_checks", lambda dev, profile: False)
    monkeypatch.setattr(cloud.subprocess, "run", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(cloud, "create_req", lambda *a, **k: calls.append("create_req"))

    result = CliRunner().invoke(cloud.deploy, ["app", "live"], input="n\n")

    assert result.exit_code != 0
    assert calls == []
