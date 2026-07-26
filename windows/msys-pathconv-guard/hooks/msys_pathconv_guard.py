r"""PreToolUse(Bash) guard: block POSIX drive paths that leak past MSYS path conversion.

THE BUG IT PREVENTS
-------------------
Git Bash converts a standalone POSIX path ARGUMENT (/c/projects/x) into Windows form
before handing it to a native Windows binary, so ordinary arguments are safe -- quoted
or not. What it cannot see, and therefore cannot convert, is a path that is:

  1. embedded in an inline script body     node -e "... '/c/projects/x' ..."
  2. built from $PWD inside such a body    node -e "... \"$PWD/x\" ..."
  3. carried in a heredoc                  python - <<'EOF' ... '/c/projects/x' ... EOF
  4. escaped with a leading double slash    //c/projects/x
  5. run under MSYS_NO_PATHCONV=1

A native binary resolves a leading "/" against the CURRENT DRIVE, so the leaked string
is written to <drive>:\c\projects\x -- silently, in the wrong place.

    $ python -c "import os; print(os.path.abspath('/c/projects/x'))"
    C:\c\projects\x
    $ node app.js /c/projects/x        # argv -> C:/projects/x   (converted, fine)
    $ node app.js "/c/projects/x"      # argv -> C:/projects/x   (quoting is irrelevant)

No MSYS or git setting fixes this: the conversion layer never sees the string.

HOW IT DECIDES
--------------
The command is tokenized quote-aware, split into pipeline segments, and only the FIRST
word of each segment is considered a command. That word must be a native Windows
interpreter, and only the argument belonging to its inline-script flag is inspected.
Everything else -- trailing path arguments, comments, regex literals, other tools'
flags -- is left alone, which is what keeps false positives at zero.

MSYS builds shipped with Git for Windows (sh, bash, dash, perl, awk, sed, grep ...)
understand /c/ natively and are deliberately never matched.

Exit 0 = allow, exit 2 = block (stderr is fed back to the model).
Any unexpected input shape exits 0: a guard must never wedge the Bash tool.
"""
import json
import re
import sys

# Native Windows interpreters: these do NOT understand /c/... (basename, .exe stripped).
NATIVE = {
    "node", "nodejs", "deno", "bun", "tsx", "ts-node",
    "python", "python3", "pythonw", "py",
    "ruby", "php", "dotnet", "pwsh", "powershell",
}

# Flags whose argument is a script body rather than a path.
# -r is excluded on purpose: for node and ruby it preloads a module PATH, which bash
# converts correctly. php is the exception, handled below.
INLINE_FLAGS = {"-e", "--eval", "-c", "--command", "-command", "-p", "-E"}

# A POSIX drive path with at least two segments: /c/projects/...
# The lookbehind keeps URLs (file:///c/x/) and deeper paths (/usr/c/x/) out; requiring a
# second slash keeps JS regex literals such as .replace(/c/g,'') out.
DRIVE_PATH = re.compile(r"(?<![A-Za-z0-9_.\\/-])/[a-z]/[^/\s'\"`;|&$]+/")

# $PWD / ${PWD} / $(pwd) / `pwd` -- expand to a POSIX path before the interpreter runs.
PWD_TOKEN = re.compile(r"\$\{?PWD\}?|\$\(\s*pwd[^)]*\)|`\s*pwd[^`]*`")

# //c/ is MSYS's explicit "do not convert this" escape.
DBL_SLASH = re.compile(r"(?<![A-Za-z0-9_.:/\\-])//[a-z]/")

# $(cygpath ...) already yields a Windows path, so its contents are safe. Stripped first,
# otherwise the recommended $(cygpath -m "$PWD") idiom would trip the $PWD rule.
SAFE_SUBST = re.compile(r"\$\(\s*cygpath\b[^)]*\)")

HEREDOC = re.compile(r"^<<-?(\w+)$")
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

SEPARATORS = "|;&\n"
MAX_HEREDOC_SCAN = 65536

ADVICE = (
    "Use a form that is valid to BOTH bash and native binaries:\n"
    "  literal   ->  C:/projects/x            (not /c/projects/x)\n"
    "  from cwd  ->  \"$(cygpath -m \"$PWD\")/x\"\n"
    "Standalone path ARGUMENTS need no change; bash already converts those, quoted or not. "
    "Only inline script bodies, heredocs and //drive/ escapes do.\n"
)


class Token:
    __slots__ = ("text", "start", "end", "parts", "sep")

    def __init__(self, text, start, end, parts, sep=False):
        self.text = text      # quotes removed
        self.start = start
        self.end = end
        self.parts = parts    # [(text, quote_char_or_None)]
        self.sep = sep

    def unquoted(self):
        return "".join(t for t, q in self.parts if q is None)

    def not_single_quoted(self):
        """Text outside single quotes -- the only place $PWD actually expands."""
        return "".join(t for t, q in self.parts if q != "'")


def tokenize(s):
    """Quote-aware shell-ish tokenizer. Linear time, tolerant of malformed input."""
    toks = []
    i, n = 0, len(s)
    parts, start = [], None

    def flush(end):
        if parts:
            toks.append(Token("".join(t for t, _ in parts), start, end, list(parts)))
            parts.clear()

    while i < n:
        ch = s[i]
        if ch in " \t\r":
            flush(i)
            start = None
            i += 1
            continue
        if ch in SEPARATORS:
            flush(i)
            start = None
            j = i + 1
            if ch in "|&" and j < n and s[j] == ch:   # && ||
                j += 1
            toks.append(Token(s[i:j], i, j, [], sep=True))
            i = j
            continue
        if start is None:
            start = i
        if ch == "\\":
            parts.append((s[i + 1:i + 2], None))
            i += 2
            continue
        if ch in "\"'":
            q, j, buf = ch, i + 1, []
            while j < n:
                if s[j] == "\\" and q == '"' and j + 1 < n:
                    buf.append(s[j + 1])
                    j += 2
                    continue
                if s[j] == q:
                    break
                buf.append(s[j])
                j += 1
            parts.append(("".join(buf), q))
            i = j + 1
            continue
        parts.append((ch, None))
        i += 1
    flush(n)
    return toks


def segments(toks):
    """Split on separator tokens; yield lists of word tokens."""
    cur = []
    for t in toks:
        if t.sep:
            if cur:
                yield cur
            cur = []
        else:
            cur.append(t)
    if cur:
        yield cur


def basename(word):
    b = re.split(r"[\\/]", word)[-1].lower()
    return b[:-4] if b.endswith(".exe") else b


def heredoc_body(cmd, tok):
    """Text between a <<DELIM token's line and its terminator, bounded."""
    m = HEREDOC.match(tok.text)
    if not m:
        return ""
    nl = cmd.find("\n", tok.end)
    if nl == -1:
        return ""
    body_start = nl + 1
    rest = cmd[body_start:body_start + MAX_HEREDOC_SCAN]
    term = re.search(r"^\s*" + re.escape(m.group(1)) + r"\s*$", rest, re.M)
    return rest[:term.start()] if term else rest


def _scan_body(text_all, text_expandable):
    """Return a reason if a script body carries an unconvertible POSIX path."""
    if DRIVE_PATH.search(SAFE_SUBST.sub("", text_all)):
        return ("a POSIX drive path is embedded in an inline script body, where bash "
                "cannot see it to convert it.")
    if PWD_TOKEN.search(SAFE_SUBST.sub("", text_expandable)):
        return ("$PWD/$(pwd) is interpolated into an inline script body. It expands to a "
                "POSIX path (/c/projects) that bash cannot convert, because it is only "
                "part of a larger string.")
    return None


def leak_reason(cmd):
    """Return an explanation string if `cmd` leaks a POSIX drive path, else None."""
    if not isinstance(cmd, str) or not cmd.strip():
        return None

    toks = tokenize(cmd)

    for t in toks:
        if t.sep:
            continue
        if t.unquoted().startswith("MSYS_NO_PATHCONV="):
            return ("MSYS_NO_PATHCONV switches off Git Bash's POSIX->Windows argv "
                    "conversion, so every /c/... argument reaches the native binary "
                    "literally.")
        m = DBL_SLASH.search(t.text)
        if m:
            return ("'%s' is MSYS's explicit do-not-convert escape, so the native binary "
                    "receives the path literally." % t.text[m.start():m.start() + 4])

    for seg in segments(toks):
        idx = 0
        while idx < len(seg) and ENV_ASSIGN.match(seg[idx].unquoted()):
            idx += 1
        if idx >= len(seg):
            continue
        cmdname = basename(seg[idx].text)
        if cmdname not in NATIVE:
            continue

        flags = set(INLINE_FLAGS)
        if cmdname == "php":
            flags.add("-r")          # php -r is code; node/ruby -r is a module path
        # PowerShell parameters are case-insensitive and may be abbreviated: -Command,
        # -command, -Co, -c all mean the same thing.
        ps_style = cmdname in ("pwsh", "powershell")
        args = seg[idx + 1:]

        def is_inline_flag(w):
            if w in flags:
                return True
            return (ps_style and len(w) > 1 and w.startswith("-")
                    and "-command".startswith(w.lower()))

        for k, a in enumerate(args):
            word = a.text

            # deno eval "<code>" / bun eval "<code>"
            if word == "eval" and cmdname in ("deno", "bun") and k + 1 < len(args):
                r = _scan_body(args[k + 1].text, args[k + 1].not_single_quoted())
                if r:
                    return r
                continue

            if is_inline_flag(word) and k + 1 < len(args):
                body = args[k + 1]
                r = _scan_body(body.text, body.not_single_quoted())
                if r:
                    return r
                continue

            if "=" in word:                       # --eval=<code>
                head, _, tail = word.partition("=")
                if is_inline_flag(head) and tail:
                    r = _scan_body(tail, tail)
                    if r:
                        return r
                continue

            if HEREDOC.match(word):
                body = heredoc_body(cmd, a)
                if DRIVE_PATH.search(body) or PWD_TOKEN.search(SAFE_SUBST.sub("", body)):
                    return ("a POSIX drive path appears in a heredoc fed to a native "
                            "interpreter; heredoc bodies are never path-converted.")
    return None


def main():
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict) or data.get("tool_name") != "Bash":
            sys.exit(0)
        tool_input = data.get("tool_input")
        if not isinstance(tool_input, dict):
            sys.exit(0)
        reason = leak_reason(tool_input.get("command"))
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)   # a guard must never wedge the Bash tool

    if not reason:
        sys.exit(0)

    sys.stderr.write(
        "Blocked: this creates a stray <drive>:\\c\\... tree instead of writing where you "
        "meant.\nReason: " + reason + "\nA native Windows binary resolves a leading '/' "
        "against the current drive, so /c/projects/x becomes C:\\c\\projects\\x.\n" + ADVICE
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
