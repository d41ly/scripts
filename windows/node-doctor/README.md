# node-doctor

A single-file environment doctor for Windows + Git Bash development machines. It detects known
per-machine gotchas — the ones that waste an afternoon because nothing errors, it just behaves
wrongly — and reports the remedy for each.

Stdlib-only, Python ≥ 3.11, no install step. Copy `doctor.py` anywhere and run it.

```bash
python doctor.py
```

```
node-doctor (read-only) - root: C:\projects\scripts  [via git]

  [ OK ] py-utf8            PYTHONUTF8/utf8-mode active (preferred encoding=utf-8).
  [skip] git-ssh            no SSH push remote configured.
  [ OK ] node-exe           node executes JS cleanly (node -e 0 -> exit 0).
  [ OK ] stale-port         port 8000 is free.
  [WARN] git-eol            no .gitattributes (autocrlf=true); nothing pins LF for files a
                            Linux container executes.
         remedy: Add .gitattributes with `*.sh text eol=lf` (plus Dockerfile*, *.conf).

  0 fail, 1 warn, 4 ok, 3 skip
```

Exit code is `0` when everything is OK or skipped, `1` when any check warns or fails — so it drops
straight into CI or a pre-push gate.

## Checks

| id | what it catches |
|---|---|
| `py-utf8` | `PYTHONUTF8` unset on a cp125x console, so inline Python charmap-crashes on non-ASCII |
| `git-ssh` | git push resolving its SSH transport to plink/PuTTY, which hangs without Pageant |
| `git-ssh-submodule` | the same, in a **submodule's own config scope** — a superproject `core.sshCommand` never reaches it, so `git-ssh` reports OK while every submodule fetch still hangs |
| `node-modules` | `node_modules` symlinks whose target does not resolve, the classic result of installing from Git Bash instead of PowerShell |
| `node-exe` | a corrupt `node.exe` **file instance** — the image mapping is torn while the bytes still hash-match, so `Get-FileHash` sees nothing and JS execution access-violates with `0xC0000005` |
| `stale-port` | a dev-server reloader outliving its parent and serving stale routes from the app port |
| `git-eol` | CRLF reaching Linux containers, where a stray CR breaks shebangs, nginx configs and `--env-file` |
| `toolchain` | which of git/node/npm/pnpm/uv are actually on PATH |

`--list` prints the registry; `--explain <id>` runs one check and shows its remedy.

## Fixes

Fixes are opt-in and guarded. Nothing mutates without `--fix` **and** an explicit `--allow <id>`.

```bash
python doctor.py --fix --allow py-utf8 --dry-run   # show the change, write nothing
python doctor.py --fix --allow py-utf8             # prompts before applying
python doctor.py --undo py-utf8                    # restore the prior value exactly
```

The guarantees, in order of how much they matter:

- **Refused under CI** (`CI` env set) and in a non-interactive shell without `--yes`.
- **`--dry-run` never writes**, and is covered by a test per fix.
- **Reversible fixes record the prior value once**, with its original registry type, so `--undo`
  restores it byte-exactly rather than guessing a default.
- **`node-exe` stages and swaps atomically.** The original is renamed aside (never deleted), the
  fresh bytes are copied to a sibling temp, then swapped in with `os.replace`. A copy that fails
  part-way can only ever leave a partial *temp*, never a truncated `node.exe`. If the replacement
  does not actually heal it, it rolls back.
- **`stale-port` re-resolves the owner PID immediately before killing** (PID-reuse window) and
  refuses anything that is not a python/node process.
- **State lives outside the repo** — `%LOCALAPPDATA%\node-doctor` / `$XDG_STATE_HOME/node-doctor` —
  so running the doctor in a checkout never dirties the tree.

Irreversible fixes (`node-modules`, `stale-port`) say so in the confirmation prompt.

## Configuration

Everything is inferred. Two things can be overridden when it can't be:

```bash
python doctor.py --port 5173          # or NODE_DOCTOR_PORT=5173
```

```jsonc
// %LOCALAPPDATA%\node-doctor\node-doctor.json  (or ./node-doctor.local.json)
// PATHS AND FLAGS ONLY -- never secrets.
{ "ssh_key_path": "~/.ssh/id_ed25519" }
```

A configured `ssh_key_path` is validated before use: a value containing a quote, a control
character, or a basename starting with `-` is rejected rather than interpolated into an
`ssh -i "<key>"` command line.

## Path resolution

The repo root comes from `git rev-parse --git-common-dir`, and the doctor walks **out** of a
`.git/**` or `.claude/worktrees/**` subtree first, so a nested checkout is never mistaken for the
main tree. Nothing is hardcoded, and invoking it from a linked worktree still operates on the main
tree. Outside a git repo it degrades cleanly: the machine-scoped checks still run and the
repo-scoped ones skip.

## Tests

```bash
python -m pytest test_doctor.py -q     # 84 tests
uvx ruff check .
```

The decision logic of each non-trivial check is a pure function (`_py_utf8_eval`,
`_classify_node_exe`, `_git_ssh_submodule_eval`), unit-tested apart from any live subprocess or
registry, so the interesting cases — a machine-wide V8 fault vs. a corrupt file instance, a
localized `netstat` State column, `:8000` vs `:18000` — are covered without needing a broken
machine to hand.

`--self-test` validates the registry and asserts the tool's own source is CR-free, so the doctor
cannot itself fall to the CRLF gotcha it diagnoses. Wire it into CI:

```bash
python doctor.py --self-test
```

## Provenance

Extracted from a private monorepo's in-repo `tools/node-doctor`, keeping the checks that are
genuinely portable and dropping the project-coupled ones. The detection and fix logic is unchanged
from the original; repo resolution, state location, the `node_modules` scan and the port check were
generalized.
