r"""Differential test: guard verdict vs. what Git Bash ACTUALLY does.

Every case runs for real through Git Bash and asks the native interpreter to resolve a
path to an absolute Windows path. Ground truth is then objective:

    resolved == expected  ->  bash converted it, the command is SAFE
    resolved != expected  ->  the POSIX string leaked, the command LEAKS

That ground truth is compared against the guard's static verdict. A mismatch is either a
false positive (guard blocks a safe command) or a false negative (a real leak gets
through) -- both are bugs.

Nothing is ever created on disk: every case only resolves and prints.

Run via PowerShell so Claude Code's own PreToolUse hook does not intercept:
    python differential_test.py
"""
import importlib.util
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD_PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    HERE, os.pardir, "hooks", "msys_pathconv_guard.py")

BASH = os.environ.get("GIT_BASH") or r"C:\Program Files\Git\bin\bash.exe"

# Must sit on C: so that a leaked "/c/..." resolves to C:\c\... rather than to a
# different drive's root. Override with DIFF_CWD if C: is not where you work.
CWD = os.environ.get("DIFF_CWD") or tempfile.gettempdir()
if not CWD.lower().startswith("c:"):
    sys.exit(f"DIFF_CWD must be on the C: drive (got {CWD})")

spec = importlib.util.spec_from_file_location("guard", GUARD_PATH)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

# Resolvers that print an absolute Windows path for their first argument / a literal.
NODE_ARG = """node -e "console.log(require('path').resolve(process.argv[1]))" """
PY_ARG = '''python -c "import os,sys; print(os.path.abspath(sys.argv[1]))" '''

DRIVE = r"C:\pr\x"                     # what /c/pr/x/ MUST become
CWDSUB = os.path.join(CWD, "sub")      # what $PWD/sub MUST become

CASES = [
    # (name, bash command, expected resolved path)
    ("node: bare posix arg",        NODE_ARG + "/c/pr/x/", DRIVE),
    ("node: double-quoted arg",     NODE_ARG + '"/c/pr/x/"', DRIVE),
    ("node: single-quoted arg",     NODE_ARG + "'/c/pr/x/'", DRIVE),
    ("node: env var",
     """P=/c/pr/x/ node -e "console.log(require('path').resolve(process.env.P))" """, DRIVE),
    ("node: inline body literal",
     """node -e "console.log(require('path').resolve('/c/pr/x/'))" """, DRIVE),
    ("node: inline body C:/ literal",
     """node -e "console.log(require('path').resolve('C:/pr/x/'))" """, DRIVE),
    ("node: $PWD in body",
     """node -e "console.log(require('path').resolve('$PWD/sub'))" """, CWDSUB),
    ("node: cygpath -m idiom",
     """node -e "console.log(require('path').resolve('$(cygpath -m "$PWD")/sub'))" """, CWDSUB),
    ("node: $PWD as an ARG",
     NODE_ARG + '"$PWD/sub"', CWDSUB),
    ("node: //drive escape",        NODE_ARG + "//c/pr/x/", DRIVE),
    ("node: MSYS_NO_PATHCONV",      "MSYS_NO_PATHCONV=1 " + NODE_ARG + "/c/pr/x/", DRIVE),
    ("node: heredoc",
     "node - <<'EOF'\nconsole.log(require('path').resolve('/c/pr/x/'))\nEOF", DRIVE),
    ("node: arg after -e body",
     """node -e "console.log(require('path').resolve(process.argv[1]))" "/c/pr/x/" """, DRIVE),

    ("py: bare posix arg",          PY_ARG + "/c/pr/x/", DRIVE),
    ("py: double-quoted arg",       PY_ARG + '"/c/pr/x/"', DRIVE),
    ("py: --flag=path style arg",   PY_ARG + "/c/pr/x/", DRIVE),
    ("py: inline body literal",
     '''python -c "import os; print(os.path.abspath('/c/pr/x/'))"''', DRIVE),
    ("py: inline body C:/ literal",
     '''python -c "import os; print(os.path.abspath('C:/pr/x/'))"''', DRIVE),
    ("py: $(pwd) in body",
     '''python -c "import os; print(os.path.abspath('$(pwd)/sub'))"''', CWDSUB),
    ("py: cygpath -w idiom",
     '''python -c "import os; print(os.path.abspath(r'$(cygpath -w "$PWD")' + '/sub'))"''', CWDSUB),
    ("py: heredoc",
     "python - <<'EOF'\nimport os\nprint(os.path.abspath('/c/pr/x/'))\nEOF", DRIVE),
    ("py: MSYS_NO_PATHCONV",        "MSYS_NO_PATHCONV=1 " + PY_ARG + "/c/pr/x/", DRIVE),
]


def run_bash(cmd):
    p = subprocess.run([BASH, "-c", cmd], capture_output=True, text=True, cwd=CWD, timeout=60)
    return (p.stdout.strip().splitlines() or [""])[-1].strip(), p.stderr.strip()


def norm(p):
    return re.sub(r"[\\/]+$", "", p).replace("/", "\\").lower()


def main():
    print("=" * 84)
    print("DIFFERENTIAL TEST  -  guard verdict vs. real Git Bash behaviour")
    print("=" * 84)
    print(f"{'case':<34} {'resolved to':<26} {'truth':<6} {'guard':<6} ok")
    print("-" * 84)

    mismatches = []
    for name, cmd, expected in CASES:
        try:
            out, err = run_bash(cmd)
        except subprocess.TimeoutExpired:
            out, err = "<timeout>", ""
        if not out:
            print(f"{name:<34} {'<no output>':<26} {'?':<6} {'?':<6} SKIP  {err[:40]}")
            continue

        truth = "SAFE" if norm(out) == norm(expected) else "LEAK"
        verdict = "BLOCK" if guard.leak_reason(cmd) else "ALLOW"
        want = "BLOCK" if truth == "LEAK" else "ALLOW"
        ok = verdict == want
        if not ok:
            mismatches.append((name, cmd, out, truth, verdict))
        print(f"{name:<34} {out[:26]:<26} {truth:<6} {verdict:<6} {'ok' if ok else 'FAIL'}")

    # MSYS interpreters must genuinely understand /c/, which is why the guard skips them.
    print("-" * 84)
    for tool, cmd in [("sh", "sh -c 'cd /c/projects && pwd -W'"),
                      ("bash", "bash -c 'cd /c/projects && pwd -W'"),
                      ("perl", """perl -e 'chdir("/c/projects") or die; print "ok"'""")]:
        out, err = run_bash(cmd)
        good = out.lower().replace("/", "\\").startswith("c:\\projects") or out == "ok"
        print(f"MSYS {tool:<8} handles /c/ natively -> {out[:30]:<32} {'ok' if good else 'FAIL'}")
        if not good:
            mismatches.append((f"msys-{tool}", cmd, out, "?", "?"))

    print()
    if mismatches:
        print(f"{len(mismatches)} MISMATCH(ES):")
        for name, cmd, out, truth, verdict in mismatches:
            print(f"  {name}\n    cmd:      {cmd!r}\n    resolved: {out}\n"
                  f"    truth={truth} guard={verdict}")
    else:
        print("NO MISMATCHES - guard agrees with real bash on every case")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
