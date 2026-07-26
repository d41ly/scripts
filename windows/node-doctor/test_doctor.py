"""Unit tests for node-doctor. Stdlib + pytest; loads doctor.py by path so it runs regardless of
pytest rootdir / which venv collects it.

    python -m pytest test_doctor.py -q
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("nd_doctor", HERE / "doctor.py")
doctor = importlib.util.module_from_spec(_spec)
# Register BEFORE exec so @dataclass resolves cls.__module__ via sys.modules (PEP 563 anns).
sys.modules["nd_doctor"] = doctor
_spec.loader.exec_module(doctor)


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """Every test gets its own state dir; nothing ever touches the real one."""
    monkeypatch.setenv("NODE_DOCTOR_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("CI", raising=False)


def _repo(root: Path, in_repo: bool = True):
    return doctor.Repo(
        main_root=root, toplevel=root, is_worktree=False, via="test", in_repo=in_repo
    )


def _ctx(root: Path, in_repo: bool = True, port: int = 8000):
    return doctor.Ctx(repo=_repo(root, in_repo), home=root, port=port)


def _fixenv(tmp_path, dry_run=True, assume_yes=False, state=None, port=8000):
    return doctor.FixEnv(
        repo=_repo(tmp_path),
        home=tmp_path,
        dry_run=dry_run,
        assume_yes=assume_yes,
        state=state if state is not None else {},
        port=port,
    )


# --- path-agnostic root resolution ------------------------------------------------------------
def test_effective_start_walks_out_of_claude_worktree():
    start = Path("X:/anywhere/proj/main/.claude/worktrees/build/tools")
    eff, note = doctor._effective_start(start)
    assert eff == Path("X:/anywhere/proj/main")
    assert note and ".claude/worktrees" in note


def test_effective_start_walks_out_of_git_dir():
    start = Path("X:/r/main/.git/modules/x")
    eff, note = doctor._effective_start(start)
    assert eff == Path("X:/r/main")
    assert note and ".git" in note


def test_effective_start_noop_for_plain_path():
    start = Path("X:/r/main/tools/node-doctor")
    eff, note = doctor._effective_start(start)
    assert eff == start and note is None


def test_resolve_repo_outside_a_repo_degrades_instead_of_exiting(tmp_path, monkeypatch):
    """The upstream original hard-exited unless it recognised its own repo signature. A standalone
    tool must still run the machine-scoped checks outside any repo."""
    monkeypatch.setattr(doctor, "_git", lambda *a, **k: None)
    repo = doctor.resolve_repo(start=tmp_path)
    assert repo.in_repo is False and repo.via == "cwd"
    assert any("not inside a git repository" in n for n in repo.notes)


def test_repo_scoped_checks_skip_outside_a_repo(tmp_path):
    ctx = _ctx(tmp_path, in_repo=False)
    for fn in (doctor.d_git_ssh, doctor.d_git_ssh_submodule, doctor.d_git_eol):
        assert fn(ctx).status == doctor.SKIP


# --- registry / self-test ---------------------------------------------------------------------
def test_registry_ids_unique_and_well_formed():
    ids = [c.id for c in doctor.REGISTRY]
    assert len(ids) == len(set(ids))
    for c in doctor.REGISTRY:
        assert c.source_ref, f"{c.id} missing source_ref"
        assert set(c.platforms) <= {"win", "posix"}
        assert callable(c.detect)
        assert c.fix is None or callable(c.fix)


def test_no_inherited_project_specific_checks():
    """The extraction dropped the checks coupled to the upstream project; keep them out."""
    ids = {c.id for c in doctor.REGISTRY}
    assert not (ids & {"pg-testdb", "node-registry", "worktrees"})


def test_own_source_is_cr_free():
    assert b"\r" not in (HERE / "doctor.py").read_bytes()


def test_source_carries_no_private_project_identifiers():
    """This tool ships in a PUBLIC repo, extracted from a private one. Guard the shapes that leak:
    absolute developer paths, internal decision-log ids, and any name supplied via
    NODE_DOCTOR_DENYLIST (comma-separated) -- so a private CI can enforce real project names
    without those names having to live in a public file."""
    import re as _re

    text = (HERE / "doctor.py").read_text(encoding="utf-8")
    assert not _re.search(r"[A-Za-z]:\\Users\\", text), "an absolute user path leaked"
    assert "/home/" not in text, "an absolute home path leaked"
    assert not _re.search(r"\b[A-Z]{3,}-\d{3}\b", text), "an internal decision-log id leaked"
    for token in filter(None, os.environ.get("NODE_DOCTOR_DENYLIST", "").split(",")):
        assert token.strip().lower() not in text.lower(), f"denylisted token {token!r} leaked"


# --- py-utf8 pure decision --------------------------------------------------------------------
def test_py_utf8_ok_when_flag_set():
    assert doctor._py_utf8_eval("1", 0, "cp1251")[0] == doctor.OK


def test_py_utf8_ok_when_utf8_mode():
    assert doctor._py_utf8_eval(None, 1, "cp1251")[0] == doctor.OK


def test_py_utf8_fail_on_cp1251_when_unset():
    status, _, remedy = doctor._py_utf8_eval(None, 0, "cp1251")
    assert status == doctor.FAIL and "PYTHONUTF8" in remedy


def test_py_utf8_warn_on_utf8_locale_when_unset():
    assert doctor._py_utf8_eval(None, 0, "utf-8")[0] == doctor.WARN


@pytest.mark.parametrize("enc", ["cp1252", "cp1250", "windows-1251"])
def test_py_utf8_fails_on_every_cp125x(enc):
    assert doctor._py_utf8_eval(None, 0, enc)[0] == doctor.FAIL


# --- git-ssh submodule pure decision ----------------------------------------------------------
def test_git_ssh_submodule_skip_when_none_checked():
    assert doctor._git_ssh_submodule_eval([], 0)[0] == doctor.SKIP


def test_git_ssh_submodule_ok_when_clean():
    assert doctor._git_ssh_submodule_eval([], 3)[0] == doctor.OK


def test_git_ssh_submodule_fail_lists_offenders():
    status, detail, remedy = doctor._git_ssh_submodule_eval([("vendor/x", "plink.exe")], 2)
    assert status == doctor.FAIL
    assert "vendor/x" in detail and "1 of 2" in detail and remedy


def test_initialized_submodules_skips_uninitialized(tmp_path, monkeypatch):
    monkeypatch.setattr(
        doctor,
        "_git",
        lambda *a, **k: "-abc123 vendor/absent\n abc123 vendor/present\n+abc123 vendor/moved",
    )
    assert doctor._initialized_submodules(tmp_path) == ["vendor/present", "vendor/moved"]


# --- node_modules discovery + dangling links ----------------------------------------------------
def _symlink_or_skip(target: Path, link: Path):
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted here (no Developer Mode/admin)")


def test_find_node_modules_discovers_nested_workspaces(tmp_path):
    for p in ("node_modules", "apps/web/node_modules", "packages/ui/node_modules"):
        (tmp_path / p).mkdir(parents=True)
    found = doctor.find_node_modules(tmp_path)
    assert len(found) == 3


def test_find_node_modules_never_descends_into_one(tmp_path):
    (tmp_path / "node_modules" / "foo" / "node_modules").mkdir(parents=True)
    found = doctor.find_node_modules(tmp_path)
    assert found == [tmp_path / "node_modules"]


def test_find_node_modules_skips_noise_dirs(tmp_path):
    (tmp_path / ".git" / "node_modules").mkdir(parents=True)
    (tmp_path / "dist" / "node_modules").mkdir(parents=True)
    assert doctor.find_node_modules(tmp_path) == []


def test_find_node_modules_respects_max_dirs(tmp_path):
    for i in range(10):
        (tmp_path / f"p{i}" / "node_modules").mkdir(parents=True)
    assert len(doctor.find_node_modules(tmp_path, max_dirs=4)) == 4


def test_dangling_links_finds_broken_and_ignores_healthy(tmp_path):
    nm = tmp_path / "node_modules"
    (nm / "healthy").mkdir(parents=True)
    _symlink_or_skip(tmp_path / "missing", nm / "broken")
    assert doctor.dangling_links(nm) == ["broken"]


def test_dangling_links_descends_scoped_packages(tmp_path):
    nm = tmp_path / "node_modules" / "@scope"
    nm.mkdir(parents=True)
    _symlink_or_skip(tmp_path / "missing", nm / "pkg")
    assert doctor.dangling_links(tmp_path / "node_modules") == ["@scope/pkg"]


def test_d_node_modules_skip_when_absent(tmp_path):
    assert doctor.d_node_modules(_ctx(tmp_path)).status == doctor.SKIP


def test_d_node_modules_ok_when_links_resolve(tmp_path):
    (tmp_path / "node_modules" / "react").mkdir(parents=True)
    assert doctor.d_node_modules(_ctx(tmp_path)).status == doctor.OK


def test_d_node_modules_fail_on_dangling_symlink(tmp_path):
    nm = tmp_path / "apps" / "web" / "node_modules"
    nm.mkdir(parents=True)
    _symlink_or_skip(tmp_path / "missing-target", nm / "next")
    res = doctor.d_node_modules(_ctx(tmp_path))
    assert res.status == doctor.FAIL and "next" in res.detail


# --- node-exe: corrupt file instance (0xC0000005) -----------------------------------------------
def test_is_access_violation_both_forms():
    assert doctor._is_access_violation(3221225477)
    assert doctor._is_access_violation(-1073741819)
    assert not doctor._is_access_violation(0)
    assert not doctor._is_access_violation(None)
    assert not doctor._is_access_violation(1)


def test_classify_node_exe_ok_when_js_runs():
    assert doctor._classify_node_exe(0, None)[0] == doctor.OK


def test_classify_node_exe_corrupt_instance_fails():
    status, detail, remedy = doctor._classify_node_exe(3221225477, 0)
    assert status == doctor.FAIL and "FILE INSTANCE" in detail and "node-exe" in remedy


def test_classify_node_exe_machine_wide_crash_warns():
    status, detail, _ = doctor._classify_node_exe(3221225477, -1073741819)
    assert status == doctor.WARN and "machine-wide" in detail


def test_classify_node_exe_other_nonzero_warns():
    assert doctor._classify_node_exe(7, None)[0] == doctor.WARN


def test_classify_node_exe_unconfirmed_copy_warns():
    assert doctor._classify_node_exe(3221225477, None)[0] == doctor.WARN


def test_d_node_exe_skip_when_node_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_node_exe_path", lambda: None)
    assert doctor.d_node_exe(_ctx(tmp_path)).status == doctor.SKIP


def test_d_node_exe_ok_does_not_pay_for_copy_probe(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_node_exe_path", lambda: Path("node.exe"))
    monkeypatch.setattr(doctor, "_exit_code", lambda *a, **k: 0)
    called = []
    monkeypatch.setattr(doctor, "_fresh_copy_exit_code", lambda p: called.append(p))
    assert doctor.d_node_exe(_ctx(tmp_path)).status == doctor.OK
    assert called == []


def test_fresh_copy_exit_code_none_when_source_missing(tmp_path):
    assert doctor._fresh_copy_exit_code(tmp_path / "nope.exe") is None


# --- guarded fixes: user env --------------------------------------------------------------------
class _FakeReg:
    def __init__(self, initial=None):
        self.values = dict(initial or {})
        self.writes = []

    def get(self, name):
        return self.values.get(name)

    def get_type(self, name):
        return 1 if name in self.values else None

    def set(self, name, value, reg_type=None):
        self.writes.append((name, value, reg_type))
        if value is None:
            self.values.pop(name, None)
        else:
            self.values[name] = value


@pytest.fixture
def fakereg(monkeypatch):
    reg = _FakeReg()
    monkeypatch.setattr(doctor, "IS_WINDOWS", True)
    monkeypatch.setattr(doctor, "_win_user_env_get", reg.get)
    monkeypatch.setattr(doctor, "_win_user_env_get_type", reg.get_type)
    monkeypatch.setattr(doctor, "_win_user_env_set", reg.set)
    return reg


def test_fix_py_utf8_posix_reports_only(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "IS_WINDOWS", False)
    o = doctor.fix_py_utf8(_fixenv(tmp_path, dry_run=True))
    assert o.would_change and not o.applied and "POSIX" in o.detail


def test_fix_py_utf8_dry_run_does_not_write(tmp_path, fakereg):
    o = doctor.fix_py_utf8(_fixenv(tmp_path, dry_run=True))
    assert o.dry_run and not o.applied and fakereg.writes == []


def test_fix_py_utf8_applies_and_records_prior(tmp_path, fakereg):
    env = _fixenv(tmp_path, dry_run=False)
    o = doctor.fix_py_utf8(env)
    assert o.applied and fakereg.values["PYTHONUTF8"] == "1"
    assert env.state["py-utf8"]["prior"] is None
    assert env.state["py-utf8"]["scope"] == "win-user-env"


def test_fix_py_utf8_idempotent(tmp_path, fakereg):
    fakereg.values["PYTHONUTF8"] = "1"
    o = doctor.fix_py_utf8(_fixenv(tmp_path, dry_run=False))
    assert not o.would_change and not o.applied


def test_apply_user_env_records_prior_only_once(tmp_path, fakereg):
    fakereg.values["X"] = "original"
    env = _fixenv(tmp_path, dry_run=False)
    doctor._apply_user_env(env, "cid", "X", "first")
    doctor._apply_user_env(env, "cid", "X", "second")
    assert env.state["cid"]["prior"] == "original"
    assert env.state["cid"]["applied"] == "second"


# --- guarded fixes: ssh -------------------------------------------------------------------------
def _write_local_config(cfg: dict) -> None:
    cfgdir = Path(os.environ["NODE_DOCTOR_STATE_DIR"])
    cfgdir.mkdir(parents=True, exist_ok=True)
    (cfgdir / "node-doctor.json").write_text(json.dumps(cfg), encoding="utf-8")


def test_ssh_key_path_accepts_a_clean_default_key(tmp_path):
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    key = ssh / "id_ed25519"
    key.write_text("k", encoding="utf-8")
    assert doctor._ssh_key_path(_fixenv(tmp_path)) == str(key)


def test_ssh_key_path_rejects_an_option_injecting_filename(tmp_path):
    """A configured path whose basename starts with '-' would be parsed by ssh as an OPTION, not a
    key. With no clean fallback the result must be None -- never the injection candidate."""
    evil = tmp_path / "-oProxyCommand=evil"
    evil.write_text("k", encoding="utf-8")
    _write_local_config({"ssh_key_path": str(evil)})
    assert doctor._ssh_key_path(_fixenv(tmp_path)) is None


def test_ssh_key_path_falls_through_injection_to_the_clean_key(tmp_path):
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    key = ssh / "id_ed25519"
    key.write_text("k", encoding="utf-8")
    evil = tmp_path / "-oProxyCommand=evil"
    evil.write_text("k", encoding="utf-8")
    _write_local_config({"ssh_key_path": str(evil)})
    assert doctor._ssh_key_path(_fixenv(tmp_path)) == str(key)


def test_fix_git_ssh_dry_run_builds_quoted_value(tmp_path, fakereg):
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    (ssh / "id_ed25519").write_text("k", encoding="utf-8")
    o = doctor.fix_git_ssh(_fixenv(tmp_path, dry_run=True))
    assert o.dry_run and "IdentitiesOnly=yes" in o.detail and "BatchMode=yes" in o.detail


def test_fix_git_ssh_no_key_reports_not_applied(tmp_path, fakereg):
    o = doctor.fix_git_ssh(_fixenv(tmp_path, dry_run=False))
    assert not o.applied and "no OpenSSH key" in o.detail


# --- guarded fixes: stale port ------------------------------------------------------------------
def test_port_owner_pid_locale_invariant_and_port_exact(monkeypatch):
    """The State column is localized; gate on the foreign-endpoint :0 shape instead. And :8000
    must not match :18000."""
    netstat = (
        "  TCP    0.0.0.0:18000    0.0.0.0:0    LISTENING                222\n"
        "  TCP    0.0.0.0:8000     0.0.0.0:0    \u041f\u0420\u041e\u0421\u041b\u0423\u0428  111\n"
        "  TCP    127.0.0.1:8000   127.0.0.1:5  ESTABLISHED              333\n"
    )
    monkeypatch.setattr(doctor, "IS_WINDOWS", True)
    monkeypatch.setattr(doctor, "_run", lambda *a, **k: netstat)
    # row 2 is the :8000 listener, matched despite a localized (non-ASCII) State column
    assert doctor._port_owner_pid(8000) == 111
    # :8000 must not match the :18000 row (suffix collision), and ESTABLISHED (foreign port != 0)
    # must never be mistaken for a listener
    assert doctor._port_owner_pid(18000) == 222
    assert doctor._port_owner_pid(9999) is None


def test_pid_is_dev_server_accepts_python_and_node(monkeypatch):
    monkeypatch.setattr(doctor, "IS_WINDOWS", True)
    monkeypatch.setattr(doctor, "_run", lambda *a, **k: '"python.exe","1234"')
    assert doctor._pid_is_dev_server(1234)
    monkeypatch.setattr(doctor, "_run", lambda *a, **k: '"sqlservr.exe","1234"')
    assert not doctor._pid_is_dev_server(1234)


def test_fix_stale_port_no_listener(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_port_owner_pid", lambda p: None)
    o = doctor.fix_stale_port(_fixenv(tmp_path, dry_run=False))
    assert not o.would_change and "no listener" in o.detail


def test_fix_stale_port_refuses_foreign_process(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_port_owner_pid", lambda p: 42)
    monkeypatch.setattr(doctor, "_pid_is_dev_server", lambda pid: False)
    o = doctor.fix_stale_port(_fixenv(tmp_path, dry_run=False))
    assert not o.applied and "refusing to kill" in o.detail


def test_fix_stale_port_success(tmp_path, monkeypatch):
    seq = iter([7, 7, None])
    monkeypatch.setattr(doctor, "_port_owner_pid", lambda p: next(seq))
    monkeypatch.setattr(doctor, "_pid_is_dev_server", lambda pid: True)
    monkeypatch.setattr(doctor, "_kill_pid", lambda pid: True)
    o = doctor.fix_stale_port(_fixenv(tmp_path, dry_run=False))
    assert o.applied and "terminated PID 7" in o.detail


def test_fix_stale_port_aborts_on_owner_change(tmp_path, monkeypatch):
    """PID-reuse window: the owner is re-resolved immediately before the kill."""
    seq = iter([7, 9])
    monkeypatch.setattr(doctor, "_port_owner_pid", lambda p: next(seq))
    monkeypatch.setattr(doctor, "_pid_is_dev_server", lambda pid: True)
    killed = []
    monkeypatch.setattr(doctor, "_kill_pid", lambda pid: killed.append(pid) or True)
    o = doctor.fix_stale_port(_fixenv(tmp_path, dry_run=False))
    assert not o.applied and "owner changed" in o.detail and killed == []


def test_fix_stale_port_reports_failure_if_still_listening(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_port_owner_pid", lambda p: 7)
    monkeypatch.setattr(doctor, "_pid_is_dev_server", lambda pid: True)
    monkeypatch.setattr(doctor, "_kill_pid", lambda pid: True)
    o = doctor.fix_stale_port(_fixenv(tmp_path, dry_run=False))
    assert not o.applied and "FAILED to terminate" in o.detail


def test_fix_stale_port_honours_custom_port(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(doctor, "_port_owner_pid", lambda p: seen.append(p) or None)
    doctor.fix_stale_port(_fixenv(tmp_path, dry_run=False, port=5173))
    assert seen == [5173]


def test_d_stale_port_reports_the_configured_port(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_port_open", lambda h, p, timeout=0.4: p == 5173)
    res = doctor.d_stale_port(_ctx(tmp_path, port=5173))
    assert res.status == doctor.WARN and "5173" in res.detail


# --- fix framework: state, CI refusal, undo -----------------------------------------------------
def test_state_lives_outside_the_repo(tmp_path):
    assert Path(os.environ["NODE_DOCTOR_STATE_DIR"]) in doctor._state_path().parents


def test_save_and_load_state_round_trip():
    doctor._save_state({"a": {"scope": "win-user-env"}})
    assert doctor._load_state()["a"]["scope"] == "win-user-env"


def test_cmd_fix_refuses_in_ci(tmp_path, monkeypatch):
    monkeypatch.setenv("CI", "1")
    assert doctor.cmd_fix(_ctx(tmp_path), ["all"], True, False) == 2


def test_cmd_fix_requires_allow(tmp_path):
    assert doctor.cmd_fix(_ctx(tmp_path), [], True, False) == 2


def test_cmd_fix_preserves_a_concurrent_writers_untouched_record(tmp_path, fakereg, monkeypatch):
    doctor._save_state({"other": {"scope": "win-user-env", "name": "OTHER"}})
    # REGISTRY holds a direct function reference, so patching the module attribute would not be
    # seen by cmd_fix -- patch the Check's own detect.
    monkeypatch.setattr(
        doctor.REGISTRY_BY_ID["py-utf8"],
        "detect",
        lambda ctx: doctor.Result("py-utf8", "t", doctor.FAIL, "d", "r", "s"),
    )
    rc = doctor.cmd_fix(_ctx(tmp_path), ["py-utf8"], assume_yes=True, dry_run=False)
    state = doctor._load_state()
    assert rc == 0
    assert "other" in state and "py-utf8" in state


def test_cmd_undo_refuses_in_ci(tmp_path, monkeypatch):
    monkeypatch.setenv("CI", "1")
    assert doctor.cmd_undo(_ctx(tmp_path), ["py-utf8"]) == 2


def test_cmd_undo_round_trip(tmp_path, fakereg):
    fakereg.values["PYTHONUTF8"] = "original"
    env = _fixenv(tmp_path, dry_run=False)
    doctor.fix_py_utf8(env)
    doctor._save_state(env.state)
    assert fakereg.values["PYTHONUTF8"] == "1"

    doctor.cmd_undo(_ctx(tmp_path), ["py-utf8"])
    assert fakereg.values["PYTHONUTF8"] == "original"
    assert "py-utf8" not in doctor._load_state()


def test_cmd_undo_dry_run_keeps_state_and_value(tmp_path, fakereg):
    env = _fixenv(tmp_path, dry_run=False)
    doctor.fix_py_utf8(env)
    doctor._save_state(env.state)
    doctor.cmd_undo(_ctx(tmp_path), ["py-utf8"], dry_run=True)
    assert fakereg.values["PYTHONUTF8"] == "1"
    assert "py-utf8" in doctor._load_state()


def test_cmd_undo_skips_unknown_id(tmp_path):
    assert doctor.cmd_undo(_ctx(tmp_path), ["nope"]) == 0


def test_undo_node_exe_missing_backup_is_a_skip(tmp_path, capsys):
    rec = {"path": str(tmp_path / "node.exe"), "backup": str(tmp_path / "gone.bak")}
    assert doctor._undo_node_exe_file("node-exe", rec, dry_run=False) is False
    assert "missing" in capsys.readouterr().out


def test_undo_node_exe_restores_backup(tmp_path):
    node = tmp_path / "node.exe"
    backup = tmp_path / "node.exe.bak"
    node.write_bytes(b"fresh")
    backup.write_bytes(b"original")
    assert doctor._undo_node_exe_file("node-exe", {"path": str(node), "backup": str(backup)}, False)
    assert node.read_bytes() == b"original" and not backup.exists()


# --- node-exe fix guards ------------------------------------------------------------------------
def test_fix_node_exe_healthy_is_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_node_exe_path", lambda: tmp_path / "node.exe")
    monkeypatch.setattr(doctor, "_exit_code", lambda *a, **k: 0)
    o = doctor.fix_node_exe(_fixenv(tmp_path, dry_run=False))
    assert not o.would_change and "already executes JS cleanly" in o.detail


def test_fix_node_exe_refuses_non_access_violation(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_node_exe_path", lambda: tmp_path / "node.exe")
    monkeypatch.setattr(doctor, "_exit_code", lambda *a, **k: 3)
    o = doctor.fix_node_exe(_fixenv(tmp_path, dry_run=False))
    assert not o.would_change and "refusing to replace" in o.detail


def test_fix_node_exe_refuses_machine_wide_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "_node_exe_path", lambda: tmp_path / "node.exe")
    monkeypatch.setattr(doctor, "_exit_code", lambda *a, **k: 3221225477)
    monkeypatch.setattr(doctor, "_fresh_copy_exit_code", lambda p: 3221225477)
    o = doctor.fix_node_exe(_fixenv(tmp_path, dry_run=False))
    assert not o.would_change and "refusing to replace" in o.detail


def test_fix_node_exe_dry_run_does_not_touch_the_file(tmp_path, monkeypatch):
    node = tmp_path / "node.exe"
    node.write_bytes(b"bytes")
    monkeypatch.setattr(doctor, "_node_exe_path", lambda: node)
    monkeypatch.setattr(doctor, "_exit_code", lambda *a, **k: 3221225477)
    monkeypatch.setattr(doctor, "_fresh_copy_exit_code", lambda p: 0)
    o = doctor.fix_node_exe(_fixenv(tmp_path, dry_run=True))
    assert o.dry_run and not o.applied
    assert node.read_bytes() == b"bytes"
    assert list(tmp_path.glob("*.node-doctor-*")) == []


def test_fix_node_exe_applies_and_records_state(tmp_path, monkeypatch):
    node = tmp_path / "node.exe"
    node.write_bytes(b"bytes")
    monkeypatch.setattr(doctor, "_node_exe_path", lambda: node)
    codes = iter([3221225477, 0])  # pre-swap crash, post-swap healthy
    monkeypatch.setattr(doctor, "_exit_code", lambda *a, **k: next(codes))
    monkeypatch.setattr(doctor, "_fresh_copy_exit_code", lambda p: 0)
    env = _fixenv(tmp_path, dry_run=False)
    o = doctor.fix_node_exe(env)
    assert o.applied and node.read_bytes() == b"bytes"
    rec = env.state["node-exe"]
    assert rec["scope"] == "node-exe-file" and Path(rec["backup"]).exists()


def test_fix_node_exe_rolls_back_when_replacement_does_not_heal(tmp_path, monkeypatch):
    node = tmp_path / "node.exe"
    node.write_bytes(b"bytes")
    monkeypatch.setattr(doctor, "_node_exe_path", lambda: node)
    monkeypatch.setattr(doctor, "_exit_code", lambda *a, **k: 3221225477)
    monkeypatch.setattr(doctor, "_fresh_copy_exit_code", lambda p: 0)
    o = doctor.fix_node_exe(_fixenv(tmp_path, dry_run=False))
    assert not o.applied and "rolled back" in o.detail
    assert node.read_bytes() == b"bytes"
    assert list(tmp_path.glob("*.node-doctor-new.*")) == []


# --- node_modules fix ---------------------------------------------------------------------------
def test_fix_node_modules_noop_when_healthy(tmp_path):
    (tmp_path / "node_modules" / "ok").mkdir(parents=True)
    o = doctor.fix_node_modules(_fixenv(tmp_path, dry_run=False))
    assert not o.would_change and "nothing to do" in o.detail


def test_fix_node_modules_dry_run_keeps_the_broken_link(tmp_path):
    nm = tmp_path / "node_modules"
    nm.mkdir()
    _symlink_or_skip(tmp_path / "missing", nm / "next")
    o = doctor.fix_node_modules(_fixenv(tmp_path, dry_run=True))
    assert o.dry_run and not o.applied and os.path.lexists(nm / "next")


def test_fix_node_modules_reports_not_applied_when_reinstall_fails(tmp_path, monkeypatch):
    nm = tmp_path / "node_modules"
    nm.mkdir()
    _symlink_or_skip(tmp_path / "missing", nm / "next")
    monkeypatch.setattr(doctor, "_run", lambda *a, **k: None)  # reinstall fails
    o = doctor.fix_node_modules(_fixenv(tmp_path, dry_run=False))
    assert not o.applied and "MORE broken" in o.detail and "reinstall FAILED" in o.detail


# --- run_checks / CLI ---------------------------------------------------------------------------
def test_run_checks_never_propagates_a_check_crash(tmp_path, monkeypatch):
    boom = doctor.Check("boom", "t", ("win", "posix"), "s", lambda ctx: 1 / 0)
    monkeypatch.setattr(doctor, "REGISTRY", [boom])
    res = doctor.run_checks(_ctx(tmp_path))
    assert res[0].status == doctor.WARN and "ZeroDivisionError" in res[0].detail


def _cli(*args):
    return subprocess.run(
        [sys.executable, str(HERE / "doctor.py"), *args],
        capture_output=True, text=True, timeout=180, cwd=str(HERE),
    )


def test_cli_list_names_every_check():
    p = _cli("--list")
    assert p.returncode == 0
    for c in doctor.REGISTRY:
        assert c.id in p.stdout


def test_cli_self_test_passes():
    p = _cli("--self-test")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "--self-test OK" in p.stdout


def test_cli_json_is_parseable_and_complete():
    p = _cli("--json")
    payload = json.loads(p.stdout)
    assert payload["schema_rev"] == doctor.SCHEMA_REV
    assert {r["id"] for r in payload["results"]} == {c.id for c in doctor.REGISTRY}
    for r in payload["results"]:
        assert r["status"] in (doctor.OK, doctor.WARN, doctor.FAIL, doctor.SKIP)


def test_cli_explain_unknown_id_exits_2():
    assert _cli("--explain", "no-such-check").returncode == 2


def test_cli_explain_known_id_works():
    p = _cli("--explain", "py-utf8")
    assert p.returncode == 0 and "py-utf8" in p.stdout


def test_cli_port_flag_reaches_the_check():
    p = _cli("--json", "--port", "5173")
    assert json.loads(p.stdout)["port"] == 5173
