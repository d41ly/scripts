# msys-pathconv-guard

Stops Git Bash on Windows from silently creating stray `C:\c\...` directory trees.

## The bug

Git Bash converts a standalone POSIX path **argument** to Windows form before handing it
to a native Windows binary — quoted or not. It cannot see a path that is not a standalone
argument, so those reach the binary untouched. A native binary resolves a leading `/`
against the **current drive**, so `/c/projects/x` gets written to `C:\c\projects\x`.

Measured, not assumed — each row is what the interpreter actually received:

| Command | Interpreter received | |
|---|---|---|
| `node app.js /c/projects/x` | `C:/projects/x` | converted |
| `node app.js "/c/projects/x"` | `C:/projects/x` | converted |
| `node app.js --out=/c/projects/x` | `C:/projects/x` | converted |
| `P=/c/projects/x node app.js` | `C:/projects/x` | converted |
| `node -e "...'/c/projects/x'..."` | `/c/projects/x` | **leaks** |
| `node -e "...'$PWD/x'..."` | `/c/projects/x` | **leaks** |
| `python - <<'EOF' … EOF` | `/c/projects/x` | **leaks** |
| `node app.js //c/projects/x` | `//c/projects/x` | **leaks** |
| `MSYS_NO_PATHCONV=1 …` | `/c/projects/x` | **leaks** |

```console
$ python -c "import os; print(os.path.abspath('/c/projects/x'))"
C:\c\projects\x
```

**No MSYS, git, or environment setting fixes this** — the conversion layer never sees the
string. `MSYS_NO_PATHCONV` makes it strictly worse. It needs two independent layers.

## What this installs

**Layer 1 — prevent.** A Claude Code `PreToolUse(Bash)` hook that rejects the five leak
shapes before they run and names the portable form to use instead.

The command is tokenized quote-aware, split into pipeline segments, and only the **first
word of each segment** is treated as a command. That word must be a native Windows
interpreter (`node`, `python`, `deno`, `bun`, `ruby`, `php`, `pwsh`, …), and only the
argument belonging to its inline-script flag is inspected. MSYS builds shipped with Git
for Windows (`sh`, `bash`, `dash`, `perl`, `awk`, `sed`, `grep`) understand `/c/`
natively and are never matched. That structure is what keeps false positives at zero:
trailing path arguments, comments, JS regex literals, URLs and other tools' flags are
all left alone.

**Layer 2 — contain.** A read-only *file* named `c`, `d`, … at each local drive root. A
file and a directory cannot share a name, so the stray directory becomes impossible to
create and the bug fails loudly at its source. This catches what a hook structurally
cannot see: paths inside script files, config files and compiled binaries, plus any
interactive Git Bash session.

## Install

```powershell
.\install.ps1
```

Idempotent, and safe to re-run. Options:

| Flag | Effect |
|---|---|
| `-Quarantine <path>` | Move existing stray `<root>\<letter>` trees there. Nothing is ever deleted. |
| `-NoCanary` | Install the hook only. |
| `-Disarm` | Remove the canary files. |
| `-DryRun` | Print what would change; write nothing. |

Arming canaries at drive roots needs admin on some nodes; it degrades gracefully and
warns. Restart Claude Code afterwards so it re-reads `settings.json` (the installer backs
it up before its first change, and merges rather than overwrites).

## Portable path forms

```bash
C:/projects/x                # instead of /c/projects/x
"$(cygpath -m "$PWD")/x"     # instead of "$PWD/x"
```

Both are valid to bash *and* to native binaries. Standalone path arguments need no
change.

## Tests

```powershell
python tests\stress_test.py hooks\msys_pathconv_guard.py
python tests\differential_test.py hooks\msys_pathconv_guard.py
```

`stress_test.py` — 72-case decision matrix (leak vectors, MSYS interpreters, portable
forms, false-positive traps), 26 malformed-input cases against the process entry point,
11 pathological inputs under a 1 s budget, and a 4000-command fuzzer.

`differential_test.py` — runs each case through **real Git Bash** and asks the
interpreter to resolve the path. Ground truth is objective (`resolved == expected` ⇒ the
command is safe), then compared against the guard's static verdict. A mismatch is a false
positive or a false negative. Requires Git for Windows; override the shell with
`GIT_BASH` and the working directory with `DIFF_CWD` (must be on `C:`).

## Notes and limits

- The hook only covers Claude Code's Bash tool. Interactive Git Bash sessions are covered
  by the canaries alone.
- A leaked `/tmp/...` or `/usr/...` lands in `C:\tmp` / `C:\usr`, which may collide with
  real directories; only single-letter drive-shaped roots are guarded.
- `//x/share/` where the host is a single letter is indistinguishable from a `//c/`
  escape and will be blocked.
- If a node legitimately needs a real `C:\d`-style directory, use `-Disarm`.
