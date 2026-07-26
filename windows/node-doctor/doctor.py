#!/usr/bin/env python3
"""node-doctor - a portable environment doctor for Windows + Git Bash dev machines.

Detects known per-machine environment/tooling gotchas and reports the remedy for each:
cp125x console crashes, plink-vs-OpenSSH git push transport (including the submodule scope that
inherits nothing), broken MSYS node_modules symlinks, a corrupt node.exe file instance, CRLF
leaking into Linux containers, and a stale listener squatting a dev port.

`--check` is READ-ONLY and is the default. Fixes are GUARDED: opt-in per id via --allow,
confirmed (or --yes), refused under CI / non-interactive, dry-run-able, and undoable where
reversible.

Design invariants:
  * Stdlib-only, Python >= 3.11. No install step; copy the file and run it.
  * PATH-AGNOSTIC. The repo root is derived from git (`--git-common-dir`), and we WALK OUT of a
    `.git/**` or `.claude/worktrees/**` subtree so a nested checkout can't be mistaken for the
    main tree. Nothing is hardcoded. Outside a repo the repo-scoped checks simply skip.
  * Sets its OWN stdout to UTF-8 and prints ASCII-only markers, so it cannot crash on a cp1251
    console before `py-utf8` has been fixed.
  * Mutable state lives OUTSIDE the repo (platform state dir), so running this in a checkout
    never dirties the tree.

Usage:
  python doctor.py                       # run all checks (read-only; default)
  python doctor.py --json                # machine-readable
  python doctor.py --list                # list the check registry
  python doctor.py --explain <id>        # detail + remedy + source for one check
  python doctor.py --self-test           # validate the registry + own source (CI)
  python doctor.py --fix --allow <id> [--dry-run] [--yes]   # guarded fix
  python doctor.py --undo <id>           # revert a reversible fix
  python doctor.py --port 5173           # port the stale-port check watches (default 8000)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# Ensure UTF-8 output regardless of the console locale (the cp1251 gotcha this tool also
# diagnoses would otherwise crash our own non-ASCII output; we additionally keep markers ASCII).
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    pass

SCHEMA_REV = 1
IS_WINDOWS = os.name == "nt"
OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"
MARKER = {OK: "[ OK ]", WARN: "[WARN]", FAIL: "[FAIL]", SKIP: "[skip]"}
DEFAULT_PORT = 8000

# STATUS_ACCESS_VIOLATION (0xC0000005): a JS-executing node.exe crash. subprocess surfaces it as
# either 3221225477 (unsigned DWORD) or -1073741819 (signed) depending on platform, so mask before
# comparing. Signature of the corrupt-node.exe-file-instance gotcha.
_ACCESS_VIOLATION = 0xC0000005

# Directories never descended when hunting for node_modules.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "dist", "build", "out",
    ".next", ".turbo", ".cache", "target", "vendor", ".pytest_cache", ".ruff_cache",
}


# --------------------------------------------------------------------------- subprocess helpers
def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 15) -> str | None:
    """Run a command WITHOUT a shell; return stripped stdout, or None on any failure/absence."""
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    return p.stdout.strip()


def _exit_code(cmd: list[str], timeout: int = 15) -> int | None:
    """Run a command WITHOUT a shell and return its RAW exit code -- which on Windows may be an
    exception code such as 0xC0000005 -- or None if the binary is absent / could not be launched.
    Unlike _run, we care about the code itself (including on a crash), not the stdout."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace"
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    return p.returncode


def _is_access_violation(code: int | None) -> bool:
    """True iff an exit code is STATUS_ACCESS_VIOLATION (0xC0000005), in either the unsigned
    (3221225477) or signed (-1073741819) form subprocess may report."""
    return code is not None and (code & 0xFFFFFFFF) == _ACCESS_VIOLATION


def _node_exe_path() -> Path | None:
    """The node executable actually on PATH (never a hardcoded node root)."""
    p = shutil.which("node")
    return Path(p).resolve() if p else None


def _fresh_copy_exit_code(node_exe: Path) -> int | None:
    """Copy node.exe to a throwaway temp path and run `<copy> -e 0`; return the copy's exit code,
    or None if the copy could not be made/run. A working copy (exit 0) while the ORIGINAL
    access-violates is the corrupt-file-INSTANCE signature: the on-disk executable image mapping of
    the specific file object is torn even though its bytes hash-match. The official win-x64 node.exe
    is self-contained, so a copy at another path is a valid standalone probe."""
    tmpdir = None
    try:
        tmpdir = Path(tempfile.mkdtemp(prefix="node-doctor-probe-"))
        probe = tmpdir / node_exe.name
        shutil.copy2(node_exe, probe)
        return _exit_code([str(probe), "-e", "0"])
    except OSError:
        return None
    finally:
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _git(args: list[str], cwd: Path) -> str | None:
    return _run(["git", *args], cwd=cwd)


def _has_crlf_issues(cwd: Path) -> bool:
    """`git diff --check` exits NON-ZERO when it finds CRLF/whitespace, so _git (which gates on rc)
    would swallow the signal; capture stdout directly, regardless of exit code."""
    try:
        p = subprocess.run(
            ["git", "diff", "--check"],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(p.stdout.strip())


def _port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _version(binary: str, *args: str) -> str | None:
    if shutil.which(binary) is None:
        return None
    out = _run([binary, *(args or ("--version",))])
    return out.splitlines()[0].strip() if out else "(present, version unknown)"


# --------------------------------------------------------------------------- repo resolution
@dataclass
class Repo:
    main_root: Path
    toplevel: Path | None
    is_worktree: bool
    via: str
    in_repo: bool = True
    notes: list[str] = field(default_factory=list)


def _effective_start(start: Path) -> tuple[Path, str | None]:
    """Walk OUT of an excluded subtree so we resolve the MAIN tree, not a nested checkout."""
    parts = list(start.parts)
    low = [p.lower() for p in parts]
    for marker, follow in ((".claude", "worktrees"), (".git", None)):
        if marker in low:
            i = low.index(marker)
            if follow is None or (i + 1 < len(low) and low[i + 1] == follow):
                outer = Path(*parts[:i]) if i > 0 else start
                return (
                    outer,
                    f"invoked from inside '{marker}"
                    f"{('/' + follow) if follow else ''}' - walked out to {outer}",
                )
    return start, None


def resolve_repo(start: Path | None = None) -> Repo:
    """Resolve the main working tree from git. Outside a repo this returns in_repo=False with
    main_root set to the starting directory, and the repo-scoped checks skip themselves."""
    start = (start or Path.cwd()).resolve()
    if start.is_file():
        start = start.parent
    eff, walk_note = _effective_start(start)
    notes = [walk_note] if walk_note else []

    common = _git(["rev-parse", "--git-common-dir"], eff)
    gitdir = _git(["rev-parse", "--absolute-git-dir"], eff)
    toplevel = _git(["rev-parse", "--show-toplevel"], eff)

    if not common:
        notes.append("not inside a git repository - repo-scoped checks will skip.")
        return Repo(eff, None, False, "cwd", in_repo=False, notes=notes)

    common_p = Path(common)
    if not common_p.is_absolute():
        common_p = (eff / common_p).resolve()
    common_p = common_p.resolve()
    main_root = common_p.parent if common_p.name == ".git" else common_p
    is_worktree = bool(gitdir and Path(gitdir).resolve() != common_p)
    repo = Repo(
        main_root.resolve(),
        Path(toplevel).resolve() if toplevel else None,
        is_worktree,
        "git",
        in_repo=True,
        notes=notes,
    )
    if repo.is_worktree:
        repo.notes.append(
            f"invoked from a linked worktree; operating on the main tree at {repo.main_root}"
        )
    return repo


# --------------------------------------------------------------------------- check framework
@dataclass
class Result:
    id: str
    title: str
    status: str
    detail: str
    remedy: str
    source_ref: str


@dataclass
class Check:
    id: str
    title: str
    platforms: tuple  # subset of {"win", "posix"}; matched against current OS
    source_ref: str
    detect: Callable[[Ctx], Result]
    fix: Callable[[FixEnv], FixOutcome] | None = None  # None => no auto-fix (report-only)
    irreversible: bool = False


@dataclass
class Ctx:
    repo: Repo
    home: Path
    port: int = DEFAULT_PORT


def _applies(check: Check) -> bool:
    want = "win" if IS_WINDOWS else "posix"
    return want in check.platforms


def _r(c: Check, status: str, detail: str, remedy: str = "") -> Result:
    return Result(c.id, c.title, status, detail, remedy, c.source_ref)


# --------------------------------------------------------------------------- detect() functions
def _py_utf8_eval(env_flag: str | None, utf8_mode: int, enc: str | None) -> tuple[str, str, str]:
    """Pure py-utf8 decision, split out so it's unit-testable apart from the live runtime."""
    cp_locale = bool(enc and enc.lower().startswith(("cp125", "cp1251", "windows-125")))
    if env_flag == "1" or utf8_mode == 1:
        return OK, f"PYTHONUTF8/utf8-mode active (preferred encoding={enc}).", ""
    if cp_locale:
        return (
            FAIL,
            f"PYTHONUTF8 unset and console default is {enc}; inline python can "
            "charmap-crash on non-ASCII.",
            "Set PYTHONUTF8=1 at USER scope. Guarded fix: --fix --allow py-utf8",
        )
    return (
        WARN,
        f"PYTHONUTF8 unset (preferred encoding={enc}); set it pre-emptively "
        "to avoid cp125x surprises.",
        "Set PYTHONUTF8=1 at USER scope. Guarded fix: --fix --allow py-utf8",
    )


def d_py_utf8(ctx: Ctx) -> Result:
    c = REGISTRY_BY_ID["py-utf8"]
    try:
        import locale

        enc = locale.getpreferredencoding(False)
    except Exception:  # noqa: BLE001
        enc = None
    status, detail, remedy = _py_utf8_eval(
        os.environ.get("PYTHONUTF8"), getattr(sys.flags, "utf8_mode", 0), enc
    )
    return _r(c, status, detail, remedy)


_PLINK = re.compile(r"plink|putty", re.IGNORECASE)
_HAS_KEYFLAG = re.compile(r"-i\s|\bIdentitiesOnly\b", re.IGNORECASE)


def _effective_ssh(cwd: Path) -> str:
    """Git's ssh-transport precedence, resolved IN A GIVEN CONFIG SCOPE:
    GIT_SSH_COMMAND > core.sshCommand (this repo's own config chain) > GIT_SSH > 'ssh'.

    The `cwd` argument is the whole point: a submodule is its own repo with its own config chain,
    so the same machine resolves a DIFFERENT transport one directory down (see d_git_ssh_submodule).
    """
    return (
        os.environ.get("GIT_SSH_COMMAND")
        or _git(["config", "--get", "core.sshCommand"], cwd)
        or os.environ.get("GIT_SSH")
        or "ssh"
    )


def _ssh_remedy(what: str) -> str:
    return (
        f"Set core.sshCommand for {what} to 'ssh -i <key> -o IdentitiesOnly=yes "
        "-o BatchMode=yes' (or GIT_SSH_COMMAND in the user env)."
    )


def d_git_ssh(ctx: Ctx) -> Result:
    c = REGISTRY_BY_ID["git-ssh"]
    if not ctx.repo.in_repo:
        return _r(c, SKIP, "not inside a git repository.")
    remotes = _git(["remote", "-v"], ctx.repo.main_root) or ""
    ssh_remote = None
    for line in remotes.splitlines():
        if "(push)" in line and re.search(r"(git@|ssh://)", line):
            ssh_remote = line.split()[0]
            break
    if not ssh_remote:
        return _r(c, SKIP, "no SSH push remote configured.")
    eff = _effective_ssh(ctx.repo.main_root)
    key_exists = any((ctx.home / ".ssh" / k).exists() for k in ("id_ed25519", "id_rsa"))
    if _PLINK.search(eff):
        return _r(
            c,
            FAIL,
            f"remote '{ssh_remote}' resolves ssh transport to '{eff}' "
            "(plink/PuTTY) - hangs without Pageant.",
            "Set GIT_SSH_COMMAND (user env) to 'ssh -i <key> "
            "-o IdentitiesOnly=yes -o BatchMode=yes'. Guarded fix: --fix --allow git-ssh",
        )
    if not _HAS_KEYFLAG.search(eff) and key_exists:
        return _r(
            c,
            WARN,
            f"ssh transport is '{eff}' (no -i/IdentitiesOnly) but an OpenSSH key "
            "exists; push may use the wrong identity.",
            "Set GIT_SSH_COMMAND (user env) to 'ssh -i <key> "
            "-o IdentitiesOnly=yes -o BatchMode=yes'. Guarded fix: --fix --allow git-ssh",
        )
    return _r(c, OK, f"ssh transport for '{ssh_remote}' resolves to '{eff}'.")


def _initialized_submodules(root: Path) -> list[str]:
    """Paths of submodules that actually have a checkout. `git submodule status` prefixes an
    UNinitialized entry with '-', and one whose gitlink differs from HEAD with '+'; only the '-'
    rows are skipped, since a '+' row still has a config scope that can hang."""
    out = _git(["submodule", "status"], root) or ""
    paths = []
    for line in out.splitlines():
        if not line.strip() or line.lstrip().startswith("-"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            paths.append(parts[1])
    return paths


def _git_ssh_submodule_eval(offenders: list[tuple[str, str]], checked: int) -> tuple[str, str, str]:
    """Pure decision, split out so it is unit-testable apart from a live repo + git."""
    if checked == 0:
        return SKIP, "no initialized submodule has an SSH remote.", ""
    if offenders:
        listed = "; ".join(f"{p} -> '{e}'" for p, e in offenders)
        return (
            FAIL,
            f"{len(offenders)} of {checked} SSH submodule(s) resolve the transport to plink/PuTTY "
            f"in their OWN config scope ({listed}) - a superproject core.sshCommand does NOT reach "
            "them, and plain plink gets no -batch, so the fetch blocks on an interactive prompt.",
            _ssh_remedy("the submodule (or globally, scoped to the host)"),
        )
    return OK, f"all {checked} SSH submodule(s) resolve to a non-plink transport.", ""


def d_git_ssh_submodule(ctx: Ctx) -> Result:
    """The `git-ssh` check above reads the SUPERPROJECT's config scope - which is exactly where a
    plink workaround gets written - so it reports OK on a machine where every submodule fetch still
    hangs. Probe each submodule's own scope instead."""
    c = REGISTRY_BY_ID["git-ssh-submodule"]
    if not ctx.repo.in_repo:
        return _r(c, SKIP, "not inside a git repository.")
    root = ctx.repo.main_root
    offenders: list[tuple[str, str]] = []
    checked = 0
    for sub in _initialized_submodules(root):
        sub_dir = root / sub
        url = _git(["config", "--get", "remote.origin.url"], sub_dir) or ""
        if not re.search(r"(git@|ssh://)", url):
            continue  # an https submodule never reaches an ssh client at all
        checked += 1
        eff = _effective_ssh(sub_dir)
        if _PLINK.search(eff):
            offenders.append((sub, eff))
    status, detail, remedy = _git_ssh_submodule_eval(offenders, checked)
    return _r(c, status, detail, remedy)


def find_node_modules(root: Path, max_dirs: int = 25, max_depth: int = 3) -> list[Path]:
    """Every node_modules directory at or under `root`, breadth-limited. Never descends INTO one
    (a nested node_modules is the package manager's business, not a workspace root)."""
    found: list[Path] = []

    def walk(d: Path, depth: int) -> None:
        if len(found) >= max_dirs or depth > max_depth:
            return
        try:
            entries = sorted(d.iterdir())
        except OSError:
            return
        for e in entries:
            if len(found) >= max_dirs:
                return
            if e.name == "node_modules":
                if e.is_dir():
                    found.append(e)
                continue
            if e.name.startswith(".") or e.name in _SKIP_DIRS or not e.is_dir():
                continue
            walk(e, depth + 1)

    walk(root, 0)
    return found


def dangling_links(nm: Path, cap: int = 500) -> list[str]:
    """First-level entries of a node_modules dir whose link target does not resolve. `@scope`
    directories are descended one level, since that is where the real package links live."""
    bad: list[str] = []
    seen = 0

    def probe(p: Path, label: str) -> None:
        # lexists==True but exists()==False => the link target is missing/unresolvable
        if os.path.lexists(p) and not p.exists():
            bad.append(label)

    try:
        entries = sorted(nm.iterdir())
    except OSError:
        return bad
    for e in entries:
        if seen >= cap:
            break
        seen += 1
        if e.name.startswith("@"):
            try:
                for s in sorted(e.iterdir()):
                    if seen >= cap:
                        break
                    seen += 1
                    probe(s, f"{e.name}/{s.name}")
            except OSError:
                continue
            continue
        probe(e, e.name)
    return bad


def d_node_modules(ctx: Ctx) -> Result:
    c = REGISTRY_BY_ID["node-modules"]
    roots = find_node_modules(ctx.repo.main_root)
    if not roots:
        return _r(c, SKIP, "no node_modules directory found.")
    broken: list[str] = []
    for nm in roots:
        for name in dangling_links(nm):
            rel = nm.parent.relative_to(ctx.repo.main_root)
            broken.append(f"{rel.as_posix() or '.'}:{name}")
    if broken:
        shown = ", ".join(broken[:8]) + (f" (+{len(broken) - 8} more)" if len(broken) > 8 else "")
        return _r(
            c,
            FAIL,
            f"{len(broken)} broken node_modules link(s) (target missing): {shown} "
            "- typically MSYS/Git-Bash symlinks.",
            "Delete the broken link(s) and reinstall from PowerShell (NOT Git Bash): "
            "`pnpm install --frozen-lockfile` / `npm ci`. "
            "Guarded (irreversible) fix: --fix --allow node-modules",
        )
    return _r(c, OK, f"{len(roots)} node_modules dir(s) scanned; all first-level links resolve.")


def _classify_node_exe(orig_code: int | None, copy_code: int | None) -> tuple[str, str, str]:
    """Pure decision for the node-exe check, split out so it's unit-testable apart from live
    subprocess. `orig_code` = exit of the INSTALLED node.exe running `-e 0`; `copy_code` = exit of a
    byte-identical temp copy (None if not run). A corrupt file INSTANCE = the original
    access-violates (0xC0000005) while a fresh copy of the SAME bytes runs cleanly (the bytes
    hash-match the official win-x64 node.exe, so Get-FileHash alone will NOT see it; the on-disk
    image mapping of the file object is torn)."""
    if orig_code == 0:
        return OK, "node executes JS cleanly (node -e 0 -> exit 0).", ""
    if not _is_access_violation(orig_code):
        return (
            WARN,
            f"node -e 0 exited {orig_code} (not the 0xC0000005 corruption signature); "
            "investigate as a separate node/JS fault.",
            "",
        )
    if copy_code == 0:
        return (
            FAIL,
            "node -e 0 access-violates (0xC0000005) but a byte-identical temp copy of node.exe "
            "runs cleanly -> the installed node.exe FILE INSTANCE is corrupt (image mapping torn; "
            "bytes hash-match, so Get-FileHash alone will not catch it).",
            "Replace the node.exe file object with a fresh copy of the same bytes: "
            "`--fix --allow node-exe` (reversible), or re-extract the win-x64 zip.",
        )
    if _is_access_violation(copy_code):
        return (
            WARN,
            "node -e 0 AND a fresh copy of node.exe both access-violate (0xC0000005) -> NOT a "
            "corrupt file instance; suspect a machine-wide V8 / DLL-injection / AV fault.",
            "Not the corrupt-file-instance class; check DLL-injection / AV. "
            "Replacing node.exe will not help.",
        )
    return (
        WARN,
        "node -e 0 access-violates (0xC0000005) but the temp-copy probe could not confirm "
        f"(copy exit {copy_code}); cannot auto-classify a corrupt file instance.",
        "Manually copy node.exe to a new path and run `<copy> -e 0`; if the copy runs, replace the "
        "installed node.exe file object.",
    )


def d_node_exe(ctx: Ctx) -> Result:
    c = REGISTRY_BY_ID["node-exe"]
    node_exe = _node_exe_path()
    if node_exe is None:
        return _r(c, SKIP, "node not found on PATH.")
    orig = _exit_code([str(node_exe), "-e", "0"])
    # only pay for the copy-probe when the original shows the access-violation signature
    copy_code = _fresh_copy_exit_code(node_exe) if _is_access_violation(orig) else None
    status, detail, remedy = _classify_node_exe(orig, copy_code)
    return _r(c, status, detail, remedy)


def d_stale_port(ctx: Ctx) -> Result:
    c = REGISTRY_BY_ID["stale-port"]
    port = ctx.port
    if _port_open("127.0.0.1", port) or _port_open("::1", port):
        return _r(
            c,
            WARN,
            f"port {port} is in use; a stale dev-server reloader here serves outdated routes.",
            f"Identify the :{port} owner PID (Windows: Get-NetTCPConnection -LocalPort {port} "
            f"-> OwningProcess; POSIX: lsof -ti tcp:{port}) and stop ONLY that PID. "
            "Guarded fix: --fix --allow stale-port",
        )
    return _r(c, OK, f"port {port} is free.")


def d_git_eol(ctx: Ctx) -> Result:
    c = REGISTRY_BY_ID["git-eol"]
    if not ctx.repo.in_repo:
        return _r(c, SKIP, "not inside a git repository.")
    has_attr = (ctx.repo.main_root / ".gitattributes").exists()
    autocrlf = _git(["config", "--get", "core.autocrlf"], ctx.repo.main_root) or "(unset)"
    crlf = _has_crlf_issues(ctx.repo.main_root)
    if crlf:
        return _r(
            c,
            WARN,
            f"`git diff --check` reports whitespace/CRLF issues (autocrlf={autocrlf}).",
            "Normalize the flagged files to LF before committing. Pin container-dangerous types "
            "(*.sh, Dockerfile*, *.conf) with `eol=lf` in .gitattributes. Report-only.",
        )
    if not has_attr:
        return _r(
            c,
            WARN,
            f"no .gitattributes (autocrlf={autocrlf}); nothing pins LF for files a Linux "
            "container executes.",
            "Add .gitattributes with `*.sh text eol=lf` (plus Dockerfile*, *.conf). "
            "A stray CR breaks shebangs, nginx and --env-file. Report-only.",
        )
    return _r(
        c,
        OK,
        f".gitattributes present, autocrlf={autocrlf}, no CRLF flagged by `git diff --check`.",
    )


def d_toolchain(ctx: Ctx) -> Result:
    c = REGISTRY_BY_ID["toolchain"]
    versions = {b: _version(b) for b in ("git", "node", "npm", "pnpm", "uv")}
    versions["python"] = sys.version.split()[0]
    present = {b: v for b, v in versions.items() if v}
    desc = "; ".join(f"{b}={v}" for b, v in present.items())
    if "git" not in present:
        return _r(
            c,
            WARN,
            f"git is NOT on PATH - every repo-scoped check will skip. Present: {desc}",
            "Install Git for Windows and ensure it is on PATH. Report-only.",
        )
    absent = [b for b, v in versions.items() if v is None]
    if absent:
        return _r(c, OK, f"{desc}  (not installed: {', '.join(absent)})")
    return _r(c, OK, desc)


# ------------------------------------------------------------ guarded fix framework
# All fixes are GUARDED: opt-in per id via --allow, confirmed (or --yes), refused under CI /
# non-interactive, dry-run-able, and (where reversible) undoable via an out-of-repo state file.
@dataclass
class FixEnv:
    repo: Repo
    home: Path
    dry_run: bool
    assume_yes: bool
    state: dict
    port: int = DEFAULT_PORT


@dataclass
class FixOutcome:
    id: str
    would_change: bool
    applied: bool
    dry_run: bool
    detail: str
    undo_hint: str = ""


def state_dir() -> Path:
    """Mutable state lives OUTSIDE any repo, so running the doctor in a checkout never dirties it.
    Override with NODE_DOCTOR_STATE_DIR (used by the tests)."""
    override = os.environ.get("NODE_DOCTOR_STATE_DIR")
    if override:
        return Path(override)
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "node-doctor"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "node-doctor"


def _state_path() -> Path:
    return state_dir() / "state.json"


def _load_state(repo: Repo | None = None) -> dict:
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(state: dict, repo: Repo | None = None) -> None:
    # atomic write (tmp + os.replace) so a concurrent reader never sees a half-written file
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def _load_local_config(env: FixEnv) -> dict:
    """Per-machine values the doctor cannot infer. PATHS/FLAGS ONLY -- never secrets."""
    for p in (state_dir() / "node-doctor.json", env.repo.main_root / "node-doctor.local.json"):
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return {}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _fs_stamp() -> str:
    """A filesystem-safe timestamp (no colons) for backup filenames; _now() carries colons."""
    return time.strftime("%Y%m%d-%H%M%S")


def _win_user_env_get(name: str) -> str | None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return winreg.QueryValueEx(k, name)[0]
    except FileNotFoundError:
        return None


def _win_user_env_get_type(name: str) -> int | None:
    """The REG_* type of an existing user-env value (so undo can restore it byte-exactly)."""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return winreg.QueryValueEx(k, name)[1]
    except FileNotFoundError:
        return None


def _win_broadcast_env_change() -> None:
    """Best-effort WM_SETTINGCHANGE so running shells pick up the change (as setx does)."""
    try:
        import ctypes

        ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x1A, 0, "Environment", 0, 1000, None)
    except Exception:  # noqa: BLE001
        pass


def _win_user_env_set(name: str, value: str | None, reg_type: int | None = None) -> None:
    import winreg

    access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, access) as k:
        if value is None:
            try:
                winreg.DeleteValue(k, name)
            except FileNotFoundError:
                pass
        else:
            # REG_SZ (literal), NOT REG_EXPAND_SZ: a value with a literal '%' (e.g. a key path
            # like C:\...100%...) must not be %-expanded by readers and corrupt the -i path.
            rt = (
                reg_type if reg_type is not None else winreg.REG_SZ
            )  # 0 (REG_NONE) must survive undo
            winreg.SetValueEx(k, name, 0, rt, value)
    _win_broadcast_env_change()


def _apply_user_env(env: FixEnv, cid: str, name: str, value: str) -> FixOutcome:
    """Set a USER-scope env var (Windows registry; persists for NEW processes). POSIX is report-only
    (no safe shell-agnostic persistence). Records prior value ONCE for exact undo; idempotent."""
    if not IS_WINDOWS:
        return FixOutcome(
            cid,
            True,
            False,
            env.dry_run,
            f'POSIX: add `export {name}="{value}"` to your shell rc '
            "(node-doctor will not auto-edit it).",
        )
    current = _win_user_env_get(name)
    if current == value:
        return FixOutcome(
            cid, False, False, env.dry_run, f"{name} already set (user scope); no change."
        )
    change = f"set user env {name}={value!r} (was {current!r})"
    if env.dry_run:
        return FixOutcome(cid, True, False, True, f"DRY-RUN: would {change}")
    rec = env.state.setdefault(cid, {})
    if "prior" not in rec:  # record the FIRST original ONCE (value + its REG type)
        rec["prior"] = current
        rec["prior_type"] = _win_user_env_get_type(name)
    rec.update({"name": name, "applied": value, "at": _now(), "scope": "win-user-env"})
    _win_user_env_set(name, value)
    return FixOutcome(
        cid,
        True,
        True,
        False,
        f"applied: {change} (new shells; running apps may need a restart / sign-out)",
        undo_hint=f"node-doctor --undo {cid}",
    )


def _ssh_key_path(env: FixEnv) -> str | None:
    explicit = _load_local_config(env).get("ssh_key_path")
    candidates = ([explicit] if explicit else []) + [
        str(env.home / ".ssh" / k) for k in ("id_ed25519", "id_rsa")
    ]
    for c in candidates:
        if not c:
            continue
        p = os.path.expanduser(c)
        # reject values that could break the -i "<key>" quoting or inject ssh options
        if '"' in p or any(ord(ch) < 32 for ch in p) or os.path.basename(p).startswith("-"):
            continue
        if Path(p).exists():
            return p
    return None


def fix_py_utf8(env: FixEnv) -> FixOutcome:
    return _apply_user_env(env, "py-utf8", "PYTHONUTF8", "1")


def fix_git_ssh(env: FixEnv) -> FixOutcome:
    key = _ssh_key_path(env)
    if not key:
        return FixOutcome(
            "git-ssh",
            True,
            False,
            env.dry_run,
            "no OpenSSH key found (set ssh_key_path in node-doctor.json); not applied.",
        )
    value = f'ssh -i "{key}" -o IdentitiesOnly=yes -o BatchMode=yes'
    return _apply_user_env(env, "git-ssh", "GIT_SSH_COMMAND", value)


def _port_owner_pid(port: int) -> int | None:
    if IS_WINDOWS:
        out = _run(["netstat", "-ano", "-p", "tcp"])
        for ln in (out or "").splitlines():
            parts = ln.split()
            # Gate on the locale-INVARIANT shape (a listening socket has foreign endpoint :0),
            # NOT the localized State string (cp1251 nodes print a non-ASCII word, not 'LISTENING').
            if (
                len(parts) >= 5
                and parts[1].endswith(f":{port}")
                and parts[2].rsplit(":", 1)[-1] == "0"
            ):
                return int(parts[-1])
        return None
    out = _run(["lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN"])
    return int(out.splitlines()[0]) if out else None


_DEV_SERVER_IMAGES = ("python.exe", "pythonw.exe", "node.exe")


def _pid_is_dev_server(pid: int) -> bool:
    """Only ever kill something that looks like a dev server we started."""
    if IS_WINDOWS:
        out = _run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]) or ""
        image = out.split(",", 1)[0].strip().strip('"').lower()  # CSV first field = image name
        return image in _DEV_SERVER_IMAGES
    out = (_run(["ps", "-p", str(pid), "-o", "comm="]) or "").strip().rsplit("/", 1)[-1].lower()
    return out.startswith(("python", "node")) or out in ("uvicorn", "gunicorn")


def _kill_pid(pid: int) -> bool:
    if IS_WINDOWS:
        return _run(["taskkill", "/PID", str(pid), "/F"]) is not None
    import signal

    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except OSError:
        return False


def fix_stale_port(env: FixEnv) -> FixOutcome:
    cid, port = "stale-port", env.port
    pid = _port_owner_pid(port)
    if pid is None:
        return FixOutcome(cid, False, False, env.dry_run, f"port {port} has no listener.")
    if not _pid_is_dev_server(pid):
        return FixOutcome(
            cid,
            False,
            False,
            env.dry_run,
            f":{port} is owned by PID {pid}, which is not a python/node process; refusing to kill.",
        )
    if env.dry_run:
        return FixOutcome(
            cid, True, False, True, f"DRY-RUN: would terminate PID {pid} on :{port}"
        )
    if _port_owner_pid(port) != pid:  # PID-reuse window: re-resolve right before killing
        return FixOutcome(
            cid, True, False, False, f":{port} owner changed since detect; aborting (re-run)."
        )
    if _kill_pid(pid) and _port_owner_pid(port) != pid:  # verify it actually died
        return FixOutcome(
            cid, True, True, False, f"terminated PID {pid} on :{port} (irreversible)"
        )
    return FixOutcome(
        cid, True, False, False, f"FAILED to terminate PID {pid} (still listening on :{port})."
    )


def fix_node_modules(env: FixEnv) -> FixOutcome:
    cid = "node-modules"
    targets = [
        (nm, dangling_links(nm)) for nm in find_node_modules(env.repo.main_root)
    ]
    targets = [(nm, bad) for nm, bad in targets if bad]
    if not targets:
        return FixOutcome(cid, False, False, env.dry_run, "no broken links; nothing to do.")
    names = ", ".join(f"{nm.parent.name}:{','.join(b)}" for nm, b in targets)
    if env.dry_run:
        return FixOutcome(
            cid,
            True,
            False,
            True,
            f"DRY-RUN: would delete broken link(s) {names} + reinstall in "
            f"{len(targets)} package dir(s)",
        )
    unlink_failed, reinstall_failed = [], []
    for nm, bad in targets:
        for name in bad:
            p = nm / name
            try:
                p.unlink()
            except OSError as e:
                unlink_failed.append(f"{name} ({type(e).__name__})")
        # invoke the package manager DIRECTLY (resolve the .cmd shim on Windows); never via a
        # -NoProfile shell that drops PATH shims.
        pkgdir = nm.parent
        if (pkgdir / "pnpm-lock.yaml").exists() or (env.repo.main_root / "pnpm-lock.yaml").exists():
            argv = [shutil.which("pnpm") or "pnpm", "install", "--frozen-lockfile"]
        else:
            argv = [shutil.which("npm") or "npm", "ci"]
        if _run(argv, cwd=pkgdir, timeout=900) is None:
            reinstall_failed.append(f"{pkgdir.name} (`{' '.join(argv[1:])}`)")
    still_bad = [n for nm, _ in targets for n in dangling_links(nm)]
    if not unlink_failed and not reinstall_failed and not still_bad:
        return FixOutcome(
            cid, True, True, False, f"deleted {names} and reinstalled (irreversible)"
        )
    why = []
    if unlink_failed:
        why.append("unlink failed: " + ", ".join(unlink_failed))
    if reinstall_failed:
        why.append("reinstall FAILED: " + ", ".join(reinstall_failed))
    if still_bad:
        why.append("links still unresolved: " + ", ".join(still_bad[:5]))
    return FixOutcome(
        cid,
        True,
        False,
        False,
        "node_modules may now be MORE broken -- " + "; ".join(why) + ". Reinstall manually.",
    )


def fix_node_exe(env: FixEnv) -> FixOutcome:
    """Replace a CORRUPT node.exe file object with a fresh copy of its own (byte-correct) bytes.
    Reversible: the original is renamed ASIDE (never deleted) and recorded in the state file, so
    --undo can restore it. Refuses unless the corrupt-file-INSTANCE signature holds NOW (original
    access-violates AND a byte-identical copy runs), so it can never touch a healthy node."""
    cid = "node-exe"
    node_exe = _node_exe_path()
    if node_exe is None:
        return FixOutcome(cid, False, False, env.dry_run, "node not on PATH; nothing to fix.")
    orig = _exit_code([str(node_exe), "-e", "0"])
    if orig == 0:
        return FixOutcome(
            cid, False, False, env.dry_run,
            f"{node_exe.name} already executes JS cleanly; nothing to fix.",
        )
    if not _is_access_violation(orig):
        return FixOutcome(
            cid, False, False, env.dry_run,
            f"{node_exe.name} -e 0 exited {orig}, not the 0xC0000005 corruption signature; "
            "refusing to replace node.exe (investigate separately).",
        )
    if _fresh_copy_exit_code(node_exe) != 0:
        return FixOutcome(
            cid, False, False, env.dry_run,
            "a fresh copy of node.exe ALSO fails to run JS -> not a corrupt file instance "
            "(suspect a machine-wide V8/DLL/AV fault); refusing to replace node.exe.",
        )
    # confirmed: the installed file access-violates while a byte-identical copy runs
    if env.dry_run:
        return FixOutcome(
            cid, True, False, True,
            f"DRY-RUN: would move {node_exe} aside (kept as backup) and copy its own byte-correct "
            "bytes into a fresh node.exe file object",
        )
    backup = node_exe.with_name(f"{node_exe.name}.node-doctor-bak.{_fs_stamp()}")
    if backup.exists():  # never overwrite an existing backup
        return FixOutcome(
            cid, True, False, False, f"backup path {backup.name} already exists; aborting.",
        )
    # Stage the fresh bytes in a SIBLING temp and swap it in atomically, so a copy that fails
    # PART-WAY (ENOSPC/quota/interrupt) can never leave node.exe as a truncated partial image --
    # only the temp is ever partial, and node.exe is either the original or the whole fresh copy.
    staging = node_exe.with_name(f"{node_exe.name}.node-doctor-new.{_fs_stamp()}")
    try:
        os.rename(node_exe, backup)  # preserve the original file object (its bytes are correct)
        shutil.copy2(backup, staging)  # fresh bytes -> a temp sibling, NOT node.exe
        os.replace(staging, node_exe)  # atomic swap-in; node.exe is never a partial file
    except OSError as e:
        # all-or-nothing rollback: drop any partial temp, then put the original back if node.exe
        # is missing (covers a failed rename, a failed copy, or a failed swap-in alike).
        if staging.exists():
            try:
                staging.unlink()
            except OSError:
                pass
        if not node_exe.exists() and backup.exists():
            try:
                os.rename(backup, node_exe)
            except OSError:
                pass
        return FixOutcome(
            cid, True, False, False,
            f"FAILED to replace node.exe ({type(e).__name__}: {e}); original restored where able.",
        )
    if _exit_code([str(node_exe), "-e", "0"]) == 0:
        rec = env.state.setdefault(cid, {})
        rec.update(
            {"scope": "node-exe-file", "path": str(node_exe), "backup": str(backup), "at": _now()}
        )
        return FixOutcome(
            cid, True, True, False,
            f"replaced the corrupt node.exe file object; {node_exe.name} -e 0 now exits 0 "
            f"(original kept at {backup.name})",
            undo_hint=f"node-doctor --undo {cid}",
        )
    try:  # the replacement did not heal it -> roll back to the original
        os.replace(backup, node_exe)
    except OSError:
        pass
    return FixOutcome(
        cid, True, False, False,
        "replaced node.exe but it still fails to run JS; rolled back to the original.",
    )


def cmd_fix(ctx: Ctx, allow: list[str], assume_yes: bool, dry_run: bool) -> int:
    if os.environ.get("CI"):
        print(
            "node-doctor: refusing --fix under CI (CI env set); "
            "fixes are a deliberate local action."
        )
        return 2
    fixable = {c.id: c for c in REGISTRY if c.fix and _applies(c)}
    targets = list(fixable) if "all" in allow else [a for a in allow if a in fixable]
    if not targets:
        avail = ", ".join(fixable) or "(none on this OS)"
        print(
            f"node-doctor --fix: select checks with --allow <id> (or --allow all). Fixable: {avail}"
        )
        return 2
    env = FixEnv(ctx.repo, ctx.home, dry_run, assume_yes, _load_state(), port=ctx.port)
    before = {k: dict(v) for k, v in env.state.items()}  # write back only ids we actually mutate
    rc = 0
    for cid in targets:
        c = fixable[cid]
        res = c.detect(ctx)
        if res.status in (OK, SKIP):
            print(f"  [skip] {cid}: nothing to fix ({res.status}: {res.detail})")
            continue
        kind = "IRREVERSIBLE" if c.irreversible else "reversible"
        if not dry_run and not assume_yes:
            if not sys.stdin.isatty():
                print(f"  [refuse] {cid}: non-interactive shell; re-run with --yes to apply.")
                rc = 2
                continue
            if input(f"  apply '{cid}' fix? [{kind}] (y/N) ").strip().lower() != "y":
                print(f"  [skip] {cid}: declined.")
                continue
        try:
            o = c.fix(env)
        except Exception as e:  # noqa: BLE001 - surface, never crash mid-batch
            print(f"  [error] {cid}: {type(e).__name__}: {e}")
            rc = 1
            continue
        tag = "dry" if o.dry_run else ("done" if o.applied else "noop")
        print(f"  [{tag}] {cid}: {o.detail}")
        if o.undo_hint:
            print(f"          undo: {o.undo_hint}")
    if not dry_run:
        touched = [k for k in env.state if env.state.get(k) != before.get(k)]
        if touched:
            merged = _load_state()  # preserve a concurrent writer's untouched-id updates
            for cid in touched:
                merged[cid] = env.state[cid]
            _save_state(merged)
    return rc


def _undo_node_exe_file(cid: str, rec: dict, dry_run: bool) -> bool:
    """Reverse fix_node_exe: drop the fresh copy and move the preserved original back into place.
    Returns True only if a real restore happened (dry-run / skip / error -> False, so the state
    record is preserved)."""
    path, backup = rec.get("path"), rec.get("backup")
    if not path or not backup:
        print(f"  [skip] {cid}: incomplete node-exe undo record.")
        return False
    path_p, backup_p = Path(path), Path(backup)
    if not backup_p.exists():
        print(f"  [skip] {cid}: backup {backup_p.name} missing; cannot restore.")
        return False
    if dry_run:
        print(f"  [dry] {cid}: would restore {path_p.name} from backup {backup_p.name}")
        return False
    try:
        if path_p.exists():
            path_p.unlink()
        os.replace(backup_p, path_p)
    except OSError as e:
        print(f"  [error] {cid}: restore FAILED ({type(e).__name__}: {e}).")
        return False
    print(f"  [undone] {cid}: restored {path_p.name} from its backup (removed the fresh copy).")
    return True


def cmd_undo(ctx: Ctx, ids: list[str], dry_run: bool = False) -> int:
    if os.environ.get("CI"):
        print(
            "node-doctor: refusing --undo under CI (CI env set); it mutates the local "
            "environment / files."
        )
        return 2
    state = _load_state()
    undone = []
    for cid in ids:
        rec = state.get(cid)
        scope = rec.get("scope") if rec else None
        if scope == "win-user-env":
            if not IS_WINDOWS:
                print(f"  [skip] {cid}: user-env undo is Windows-only here.")
                continue
            if dry_run:
                print(f"  [dry] {cid}: would restore {rec['name']} to {rec.get('prior')!r}")
                continue
            _win_user_env_set(rec["name"], rec.get("prior"), rec.get("prior_type"))
            print(f"  [undone] {cid}: restored {rec['name']} to {rec.get('prior')!r}")
            undone.append(cid)
        elif scope == "node-exe-file":
            if _undo_node_exe_file(cid, rec, dry_run):
                undone.append(cid)
        else:
            print(f"  [skip] {cid}: no reversible record to undo.")
    if undone:  # re-load + drop only the undone ids (preserve a concurrent writer's records)
        fresh = _load_state()
        for cid in undone:
            fresh.pop(cid, None)
        _save_state(fresh)
    return 0


# --------------------------------------------------------------------------- registry
REGISTRY: list[Check] = [
    Check(
        "py-utf8",
        "Python UTF-8 mode (cp125x charmap crash)",
        ("win",),
        "Windows console defaults to a cp125x codepage",
        d_py_utf8,
        fix=fix_py_utf8,
    ),
    Check(
        "git-ssh",
        "Git push SSH transport (plink vs OpenSSH)",
        ("win", "posix"),
        "GIT_SSH_COMMAND > core.sshCommand > GIT_SSH > ssh",
        d_git_ssh,
        fix=fix_git_ssh,
    ),
    Check(
        "git-ssh-submodule",
        "Submodule SSH transport (its config scope inherits nothing)",
        ("win", "posix"),
        "a submodule is its own repo with its own config chain",
        d_git_ssh_submodule,
        # Report-only: the remedy is a per-machine choice between a global setting, a host-scoped
        # includeIf, and a submodule-local one - not something to pick on the operator's behalf.
    ),
    Check(
        "node-modules",
        "MSYS broken node_modules symlinks",
        ("win", "posix"),
        "a Git-Bash install can create unresolvable symlinks",
        d_node_modules,
        fix=fix_node_modules,
        irreversible=True,
    ),
    Check(
        "node-exe",
        "Corrupt node.exe file instance (JS-exec 0xC0000005)",
        ("win",),
        "torn image mapping; bytes still hash-match",
        d_node_exe,
        fix=fix_node_exe,
        # reversible: the original file is renamed aside + recorded, so --undo restores it
    ),
    Check(
        "stale-port",
        "Stale dev-server holding the app port",
        ("win", "posix"),
        "a uvicorn/vite reloader can outlive its parent",
        d_stale_port,
        fix=fix_stale_port,
        irreversible=True,
    ),
    Check(
        "git-eol",
        "CRLF into Linux containers",
        ("win", "posix"),
        "a stray CR breaks shebangs, nginx and --env-file",
        d_git_eol,
    ),
    Check(
        "toolchain",
        "Toolchain presence (git/node/npm/pnpm/uv)",
        ("win", "posix"),
        "PATH inventory",
        d_toolchain,
    ),
]
REGISTRY_BY_ID = {c.id: c for c in REGISTRY}


# --------------------------------------------------------------------------- modes
def run_checks(ctx: Ctx) -> list[Result]:
    results = []
    for c in REGISTRY:
        if not _applies(c):
            results.append(
                _r(c, SKIP, f"not applicable on {'Windows' if IS_WINDOWS else 'POSIX'}.")
            )
            continue
        try:
            results.append(c.detect(ctx))
        except Exception as e:  # noqa: BLE001 - a check must never crash the doctor
            results.append(
                _r(
                    c,
                    WARN,
                    f"check raised {type(e).__name__}: {e}",
                    "report this as a node-doctor bug.",
                )
            )
    return results


def cmd_check(ctx: Ctx, as_json: bool) -> int:
    results = run_checks(ctx)
    if as_json:
        print(
            json.dumps(
                {
                    "schema_rev": SCHEMA_REV,
                    "main_root": str(ctx.repo.main_root),
                    "resolved_via": ctx.repo.via,
                    "in_repo": ctx.repo.in_repo,
                    "port": ctx.port,
                    "notes": ctx.repo.notes,
                    "results": [r.__dict__ for r in results],
                },
                indent=2,
            )
        )
    else:
        print(f"node-doctor (read-only) - root: {ctx.repo.main_root}  [via {ctx.repo.via}]")
        for note in ctx.repo.notes:
            print(f"  note: {note}")
        print()
        for r in results:
            print(f"  {MARKER[r.status]} {r.id:<18} {r.detail}")
            if r.remedy and r.status in (WARN, FAIL):
                print(f"         remedy: {r.remedy}")
        n_fail = sum(1 for r in results if r.status == FAIL)
        n_warn = sum(1 for r in results if r.status == WARN)
        print(
            f"\n  {n_fail} fail, {n_warn} warn, {sum(1 for r in results if r.status == OK)} ok, "
            f"{sum(1 for r in results if r.status == SKIP)} skip"
        )
    return 1 if any(r.status in (FAIL, WARN) for r in results) else 0


def cmd_list() -> int:
    print("node-doctor checks:")
    for c in REGISTRY:
        fixable = "fix" if c.fix else "report-only"
        print(
            f"  {c.id:<18} [{','.join(c.platforms):<10}] {c.title}\n"
            f"  {'':<18}  {fixable}; source: {c.source_ref}"
        )
    return 0


def cmd_explain(check_id: str, ctx: Ctx) -> int:
    c = REGISTRY_BY_ID.get(check_id)
    if not c:
        print(f"unknown check id '{check_id}'. Run --list.")
        return 2
    r = c.detect(ctx) if _applies(c) else _r(c, SKIP, "not applicable on this OS.")
    print(
        f"{c.id}: {c.title}\n  platforms: {','.join(c.platforms)}\n  source: {c.source_ref}\n"
        f"  status: {MARKER[r.status]} {r.detail}\n  remedy: {r.remedy or '(none)'}"
    )
    return 0


def cmd_self_test(ctx: Ctx) -> int:
    problems = []
    seen = set()
    for c in REGISTRY:
        if c.id in seen:
            problems.append(f"duplicate check id: {c.id}")
        seen.add(c.id)
        if not c.source_ref:
            problems.append(f"{c.id}: empty source_ref")
        if not set(c.platforms) <= {"win", "posix"}:
            problems.append(f"{c.id}: bad platforms {c.platforms}")
        if not callable(c.detect):
            problems.append(f"{c.id}: detect not callable")
        if c.fix is not None and not callable(c.fix):
            problems.append(f"{c.id}: fix not callable")
    # the tool's own source must be CR-free (it must not fall to the CRLF gotcha it diagnoses)
    if b"\r" in Path(__file__).read_bytes():
        problems.append("doctor.py contains CR bytes (must be LF-only; pin in .gitattributes)")
    if problems:
        print("node-doctor --self-test FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(
        f"node-doctor --self-test OK: {len(REGISTRY)} checks, schema_rev={SCHEMA_REV}; "
        "source CR-free."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="node-doctor",
        description="Portable environment doctor for Windows + Git Bash dev machines.",
    )
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="run all checks (default)")
    g.add_argument("--list", action="store_true", help="list the check registry")
    g.add_argument("--explain", metavar="ID", help="explain one check")
    g.add_argument(
        "--self-test", action="store_true", help="validate the registry + own source (CI)"
    )
    g.add_argument("--fix", action="store_true", help="apply guarded fixes (choose with --allow)")
    g.add_argument(
        "--undo", metavar="ID", action="append", help="undo a previously-applied reversible fix"
    )
    ap.add_argument(
        "--allow",
        metavar="ID",
        action="append",
        default=[],
        help="check id(s) --fix may act on, or 'all' (repeatable)",
    )
    ap.add_argument("--yes", action="store_true", help="skip the per-fix confirmation prompt")
    ap.add_argument(
        "--dry-run", action="store_true", help="with --fix: print the change without applying"
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output (with --check)")
    ap.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("NODE_DOCTOR_PORT") or DEFAULT_PORT),
        help=f"port the stale-port check watches (default {DEFAULT_PORT})",
    )
    args = ap.parse_args(argv)

    if args.list:
        return cmd_list()

    ctx = Ctx(repo=resolve_repo(), home=Path.home(), port=args.port)

    if args.fix:
        return cmd_fix(ctx, args.allow, args.yes, args.dry_run)
    if args.undo:
        return cmd_undo(ctx, args.undo, args.dry_run)
    if args.self_test:
        return cmd_self_test(ctx)
    if args.explain:
        return cmd_explain(args.explain, ctx)
    return cmd_check(ctx, as_json=args.json)


if __name__ == "__main__":
    sys.exit(main())
