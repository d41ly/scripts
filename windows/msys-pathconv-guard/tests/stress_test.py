r"""Stress test for msys_pathconv_guard.py.

Runs the guard's decision function over a large matrix of command shapes, then hammers
the process-level entry point with malformed input, pathological sizes and a fuzzer.

    python stress_test.py [path\to\msys_pathconv_guard.py]

BLOCK = guard must reject (a real leak), ALLOW = guard must let it through.
"""
import importlib.util
import json
import os
import random
import string
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD_PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "msys_pathconv_guard.py")

spec = importlib.util.spec_from_file_location("guard", GUARD_PATH)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

BLOCK, ALLOW = "BLOCK", "ALLOW"

# ---------------------------------------------------------------------------
# 1. Decision matrix
# ---------------------------------------------------------------------------
CASES = [
    # ---- A. inline script bodies: the primary leak vector -------------------
    ("inline", BLOCK, "node -e", '''node -e "require('fs').mkdirSync('/c/projects/out/')"'''),
    ("inline", BLOCK, "node --eval", '''node --eval "fs.mkdirSync('/c/projects/out/')"'''),
    ("inline", BLOCK, "node -p", '''node -p "require('/c/projects/pkg/x.json')"'''),
    ("inline", BLOCK, "python -c", '''python -c "open('/c/projects/var/a.db','w')"'''),
    ("inline", BLOCK, "python3 -c", '''python3 -c "import os; os.makedirs('/c/tmp/out/')"'''),
    ("inline", BLOCK, "py -c", '''py -c "open('/c/projects/var/a.db','w')"'''),
    ("inline", BLOCK, "ruby -e", '''ruby -e "Dir.mkdir('/c/projects/out/')"'''),
    ("inline", BLOCK, "php -r", '''php -r "mkdir('/c/projects/out/');"'''),
    ("inline", BLOCK, "bun -e", '''bun -e "Bun.write('/c/projects/out/x','')"'''),
    ("inline", BLOCK, "deno --eval", '''deno --eval "Deno.mkdirSync('/c/projects/out/')"'''),
    ("inline", BLOCK, "tsx -e", '''tsx -e "fs.mkdirSync('/c/projects/out/')"'''),
    ("inline", BLOCK, "pwsh -Command", '''pwsh -Command "mkdir '/c/projects/out/'"'''),
    ("inline", BLOCK, "absolute interpreter path", '''/usr/bin/python -c "open('/c/projects/x/y')"'''),
    ("inline", BLOCK, "single-quoted body", """python -c 'open("/c/projects/var/a.db","w")'"""),
    ("inline", BLOCK, "deep path", '''node -e "fs.statSync('/c/Users/me/AppData/Local/x/')"'''),
    ("inline", BLOCK, "nested quotes in body", '''node -e "console.log(\\"/c/projects/out/\\")"'''),
    ("inline", BLOCK, "body after other flags", '''node --no-warnings -e "fs.mkdirSync('/c/projects/o/')"'''),

    # ---- B. $PWD-family interpolation --------------------------------------
    ("pwd", BLOCK, "$PWD in body", '''node -e "console.log('$PWD/sub')"'''),
    ("pwd", BLOCK, "${PWD} in body", '''node -e "console.log('${PWD}/sub')"'''),
    ("pwd", BLOCK, "$(pwd) in body", '''python -c "open('$(pwd)/out.txt','w')"'''),
    ("pwd", BLOCK, "backtick pwd in body", '''python -c "open('`pwd`/out.txt','w')"'''),

    # ---- C. conversion disabled / escaped ----------------------------------
    ("escape", BLOCK, "MSYS_NO_PATHCONV prefix", "MSYS_NO_PATHCONV=1 node app.js /c/projects/x"),
    ("escape", BLOCK, "MSYS_NO_PATHCONV export", "export MSYS_NO_PATHCONV=1; node app.js /c/projects/x"),
    ("escape", BLOCK, "//drive/ escape", "node app.js //c/projects/x"),
    ("escape", BLOCK, "//drive/ in cp", "cp file.txt //d/backup/dir/"),

    # ---- D. heredocs --------------------------------------------------------
    ("heredoc", BLOCK, "<<EOF", "python - <<EOF\nopen('/c/projects/x/y','w')\nEOF"),
    ("heredoc", BLOCK, "<<'EOF' quoted", "python - <<'EOF'\nopen('/c/projects/x/y','w')\nEOF"),
    ("heredoc", BLOCK, "<<-EOF dash", "python - <<-EOF\n\topen('/c/projects/x/y','w')\nEOF"),
    ("heredoc", BLOCK, "heredoc with $PWD", "node - <<'EOF'\nconsole.log('$PWD/x')\nEOF"),

    # ---- E. command segmentation -------------------------------------------
    ("segment", BLOCK, "after pipe", '''ls -la | node -e "console.log('/c/projects/x/')"'''),
    ("segment", BLOCK, "after &&", '''cd /tmp && node -e "console.log('/c/projects/x/')"'''),
    ("segment", BLOCK, "after ;", '''echo hi; python -c "open('/c/projects/x/y')"'''),
    ("segment", BLOCK, "after ||", '''false || node -e "console.log('/c/projects/x/')"'''),
    ("segment", BLOCK, "after newline", '''echo hi\nnode -e "console.log('/c/projects/x/')"'''),
    ("segment", BLOCK, "2nd interpreter leaks", '''node -e "console.log(1)" && python -c "open('/c/p/x/y')"'''),

    # ---- F. legitimate: bash converts standalone ARGS ----------------------
    ("arg", ALLOW, "bare posix arg", "node script.js /c/projects/x"),
    ("arg", ALLOW, "double-quoted posix arg", 'node script.js "/c/projects/x"'),
    ("arg", ALLOW, "single-quoted posix arg", "node script.js '/c/projects/x'"),
    ("arg", ALLOW, "--flag=posix arg", "node script.js --out=/c/projects/x"),
    ("arg", ALLOW, "posix arg to interpreter", "python /c/projects/build.py"),
    ("arg", ALLOW, "arg AFTER an -e body", '''node -e "console.log(1)" "/c/projects/data.json"'''),
    ("arg", ALLOW, "sq arg AFTER an -e body", """node -e "console.log(1)" '/c/projects/data.json'"""),
    ("arg", ALLOW, "-r preload then posix arg", '''node -r ts-node/register app.js /c/projects/x'''),

    # ---- G. legitimate: MSYS interpreters understand /c/ -------------------
    ("msys", ALLOW, "sh -c", "sh -c 'ls /c/projects/sub/'"),
    ("msys", ALLOW, "bash -c", "bash -c 'cd /c/projects/sub/ && ls'"),
    ("msys", ALLOW, "dash -c", "dash -c 'ls /c/projects/sub/'"),
    ("msys", ALLOW, "perl -e", """perl -e 'opendir(D, "/c/projects/sub/")'"""),
    ("msys", ALLOW, "sed -e", "sed -e 's|/c/projects/x/|Y|' in.txt"),
    ("msys", ALLOW, "awk", """awk '{print "/c/projects/x/"}' in.txt"""),
    ("msys", ALLOW, "sed -f script.py -e", "sed -f gen.py -e 's|/c/projects/x/|Y|' in.txt"),
    ("msys", ALLOW, "grep -e posix", "grep -e '/c/projects/x/' log.txt"),

    # ---- H. legitimate: portable forms -------------------------------------
    ("portable", ALLOW, "C:/ literal in body", '''node -e "fs.mkdirSync('C:/projects/out/')"'''),
    ("portable", ALLOW, "cygpath -m idiom", '''node -e "console.log('$(cygpath -m \\"$PWD\\")/sub')"'''),
    ("portable", ALLOW, "cygpath -w idiom", '''python -c "print('$(cygpath -w "$PWD")')"'''),
    ("portable", ALLOW, "backslash win path", r'''node -e "fs.mkdirSync('C:\\projects\\out')"'''),

    # ---- I. false-positive traps -------------------------------------------
    ("trap", ALLOW, "JS regex /c/g", '''node -e "console.log('abc'.replace(/c/g,''))"'''),
    ("trap", ALLOW, "JS regex /a/ then /b/", '''node -e "x.split(/a/).join('-')"'''),
    ("trap", ALLOW, "http URL", '''node -e "fetch('http://cdn.example.com/x/')"'''),
    ("trap", ALLOW, "https URL single letter host", '''node -e "fetch('https://a/b/')"'''),
    ("trap", ALLOW, "file:/// URL", '''node -e "fetch('file:///c/projects/x/')"'''),
    ("trap", ALLOW, "UNC share", "cp file.txt //fileserver/share/dir/"),
    ("trap", ALLOW, "docker named pipe", 'docker -H "npipe:////./pipe/docker_engine" ps'),
    ("trap", ALLOW, "interpreter inside a quote", """echo "python -c '/c/projects/x/'" """),
    ("trap", ALLOW, "mypy is not py", "mypy -c 'x=1' --strict"),
    ("trap", ALLOW, "numpy is not py", "echo numpy -c /c/projects/x/"),
    ("trap", ALLOW, "posix path in a comment", '''node -e "console.log(1)" # see /c/projects/x/'''),
    ("trap", ALLOW, "no interpreter", "cd /c/projects && git status"),
    ("trap", ALLOW, "echo posix path", "echo /c/projects/x/"),
    ("trap", ALLOW, "rsync exclude", "rsync -a --exclude=/c/projects/x/ src/ dst/"),
    ("trap", ALLOW, "single-segment /c/x", '''node -e "console.log('/c/x')"'''),
    ("trap", ALLOW, "empty command", ""),
    ("trap", ALLOW, "whitespace only", "   \n\t "),
]


def run_matrix():
    print("=" * 78)
    print("1. DECISION MATRIX")
    print("=" * 78)
    by_cat, failures = {}, []
    for cat, want, name, cmd in CASES:
        try:
            got = BLOCK if guard.leak_reason(cmd) else ALLOW
        except Exception as e:
            got = f"CRASH:{type(e).__name__}"
        ok = got == want
        st = by_cat.setdefault(cat, [0, 0])
        st[0] += 1
        if ok:
            st[1] += 1
        else:
            failures.append((cat, name, want, got, cmd))
    for cat, (total, passed) in by_cat.items():
        mark = "ok " if passed == total else "FAIL"
        print(f"  [{mark}] {cat:<9} {passed}/{total}")
    if failures:
        print("\n  --- failures ---")
        for cat, name, want, got, cmd in failures:
            print(f"  [{cat}] {name}\n      want={want} got={got}\n      cmd: {cmd!r}")
    return len(failures)


# ---------------------------------------------------------------------------
# 2. Process-level robustness: the guard must never wedge the Bash tool
# ---------------------------------------------------------------------------
MALFORMED = [
    ("empty stdin", ""),
    ("not json", "this is not json at all"),
    ("truncated json", '{"tool_name": "Bash", "tool_input":'),
    ("json list", "[1,2,3]"),
    ("json string", '"hello"'),
    ("json number", "42"),
    ("json null", "null"),
    ("json true", "true"),
    ("no tool_name", json.dumps({"tool_input": {"command": "node -e \"'/c/p/x/'\""}})),
    ("tool_name null", json.dumps({"tool_name": None, "tool_input": {"command": "x"}})),
    ("no tool_input", json.dumps({"tool_name": "Bash"})),
    ("tool_input null", json.dumps({"tool_name": "Bash", "tool_input": None})),
    ("tool_input list", json.dumps({"tool_name": "Bash", "tool_input": [1, 2]})),
    ("command null", json.dumps({"tool_name": "Bash", "tool_input": {"command": None}})),
    ("command number", json.dumps({"tool_name": "Bash", "tool_input": {"command": 12345}})),
    ("command list", json.dumps({"tool_name": "Bash", "tool_input": {"command": ["a", "b"]}})),
    ("command dict", json.dumps({"tool_name": "Bash", "tool_input": {"command": {"a": 1}}})),
    ("command bool", json.dumps({"tool_name": "Bash", "tool_input": {"command": True}})),
    ("unicode", json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo 日本語 🎉 café"}})),
    ("crlf", json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo a\r\nnode -e \"1\""}})),
    ("unterminated dq", json.dumps({"tool_name": "Bash", "tool_input": {"command": 'node -e "unclosed'}})),
    ("unterminated sq", json.dumps({"tool_name": "Bash", "tool_input": {"command": "node -e 'unclosed"}})),
    ("trailing backslash", json.dumps({"tool_name": "Bash", "tool_input": {"command": "node -e \"x\"\\"}})),
    ("unbalanced subst", json.dumps({"tool_name": "Bash", "tool_input": {"command": 'node -e "$(cygpath -m"'}})),
    ("null byte", json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo a\u0000b"}})),
    ("deep nesting", json.dumps({"tool_name": "Bash", "tool_input": {"command": "x"}, "extra": {"a": {"b": {"c": 1}}}})),
]


def run_process_level():
    print()
    print("=" * 78)
    print("2. PROCESS-LEVEL ROBUSTNESS  (must exit 0 or 2, never crash/hang)")
    print("=" * 78)
    fails = 0
    for name, payload in MALFORMED:
        try:
            p = subprocess.run([sys.executable, GUARD_PATH], input=payload,
                               capture_output=True, text=True, timeout=15)
            rc = p.returncode
            ok = rc in (0, 2)
            tail = ""
            if not ok:
                tail = " | " + (p.stderr.strip().splitlines() or [""])[-1][:90]
        except subprocess.TimeoutExpired:
            rc, ok, tail = "TIMEOUT", False, ""
        if not ok:
            fails += 1
        print(f"  [{'ok ' if ok else 'FAIL'}] exit={rc:<7} {name}{tail}")
    return fails


# ---------------------------------------------------------------------------
# 3. Performance / ReDoS
# ---------------------------------------------------------------------------
def run_perf():
    print()
    print("=" * 78)
    print("3. PERFORMANCE  (pathological inputs, budget 1.0s each)")
    print("=" * 78)
    pathological = [
        ("40k quoted spans", 'node -e ' + '"a" ' * 40000),
        ("200k plain chars", "node -e " + "a" * 200000),
        ("many interpreters", "node -e 'x'; " * 5000),
        ("nested quote soup", 'node -e "' + "'\\\"" * 20000 + '"'),
        ("long single quote", "node -e '" + "x" * 200000 + "'"),
        ("unterminated + long", 'node -e "' + "x" * 200000),
        ("repeated $(cygpath", 'node -e "' + '$(cygpath -m "$PWD")' * 5000 + '"'),
        ("many pwd tokens", 'node -e "' + "$PWD" * 20000 + '"'),
        ("drive paths galore", 'node -e "' + "/c/a/b/ " * 20000 + '"'),
        ("backslash run", "node -e " + "\\" * 100000),
        ("pipe storm", "node -e 'x' | " * 5000 + "cat"),
    ]
    fails = 0
    for name, cmd in pathological:
        t0 = time.perf_counter()
        try:
            guard.leak_reason(cmd)
            err = None
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
        dt = time.perf_counter() - t0
        ok = err is None and dt < 1.0
        if not ok:
            fails += 1
        note = f" {err}" if err else ""
        print(f"  [{'ok ' if ok else 'FAIL'}] {dt*1000:8.1f} ms  {len(cmd):>7} chars  {name}{note}")
    return fails


# ---------------------------------------------------------------------------
# 4. Fuzz: never crash, never hang, and never block a command with no /x/ path
# ---------------------------------------------------------------------------
def run_fuzz(n=4000, seed=1337):
    print()
    print("=" * 78)
    print(f"4. FUZZ  ({n} random commands)")
    print("=" * 78)
    rnd = random.Random(seed)
    atoms = [
        "node", "python", "sh", "bash", "-e", "-c", '"', "'", "`", "$", "(", ")",
        "|", "&&", ";", "\n", "/c/", "/x/y/", "C:/", "$PWD", "$(pwd)", "$(cygpath -m",
        "//c/", "MSYS_NO_PATHCONV=1", "<<EOF", "EOF", "\\", "#", "=", " ", "..",
        "echo", "git", ".py", "http://a/b/", "日本", "\x00",
    ]
    crashes, slow, bogus = [], [], []
    for _ in range(n):
        cmd = "".join(rnd.choice(atoms) for _ in range(rnd.randint(1, 60)))
        t0 = time.perf_counter()
        try:
            reason = guard.leak_reason(cmd)
        except Exception as e:
            crashes.append((cmd, f"{type(e).__name__}: {e}"))
            continue
        dt = time.perf_counter() - t0
        if dt > 0.5:
            slow.append((cmd, dt))
        # A block is only ever defensible if the command contains one of the
        # trigger substrings. Blocking anything else would be a phantom verdict.
        if reason and not any(t in cmd for t in ("/", "PWD", "pwd", "MSYS_NO_PATHCONV")):
            bogus.append((cmd, reason))
    for label, items in (("crash", crashes), ("slow", slow), ("phantom block", bogus)):
        print(f"  {label:<14} {len(items)}")
        for cmd, info in items[:3]:
            print(f"      {cmd[:70]!r} -> {str(info)[:70]}")
    return len(crashes) + len(slow) + len(bogus)


if __name__ == "__main__":
    total = run_matrix() + run_process_level() + run_perf() + run_fuzz()
    print()
    print("=" * 78)
    print("ALL STRESS TESTS PASSED" if total == 0 else f"{total} FAILURE(S)")
    print("=" * 78)
    sys.exit(0 if total == 0 else 1)
