"""Security rules: secrets, dangerous calls, weak crypto, committed env files, risky deps."""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator

from audit_agent.models import Category, Finding, Severity
from audit_agent.rules.base import CODE, PY, FileRule, RegexRule, RepoRule, Rule, dotted_name
from audit_agent.workspace import Repo, SourceFile

S = Category.SECURITY
NOT_PY = CODE - PY  # Python gets precise AST versions of some checks


# --------------------------------------------------------------------------- secrets

# (name, regex) pairs for well-known credential formats. High precision, so CRITICAL.
_TOKEN_PATTERNS: list[tuple[str, str]] = [
    ("AWS access key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("OpenAI-style API key", r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Stripe live key", r"\b[rs]k_live_[0-9A-Za-z]{20,}\b"),
    ("Private key block", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]

# Values that are obviously not real secrets.
_PLACEHOLDER = re.compile(
    r"(xxx|\*\*\*|<.*>|\$\{|\{\{|changeme|change_me|example|dummy|placeholder|your[_-]|redacted|os\.environ|getenv|process\.env)",
    re.IGNORECASE,
)


class KnownTokenRule(FileRule):
    id = "SEC001"
    title = "Hardcoded credential"
    severity = Severity.CRITICAL
    category = S

    def __init__(self) -> None:
        self._patterns = [(name, re.compile(rx)) for name, rx in _TOKEN_PATTERNS]

    def check(self, file: SourceFile) -> Iterator[Finding]:
        for lineno, line in enumerate(file.lines, start=1):
            for name, rx in self._patterns:
                if rx.search(line) and not _PLACEHOLDER.search(line):
                    yield self.finding(file.path, lineno, f"{name} committed to source. Rotate it and load from a secret store.", line)
                    break


class SecretAssignmentRule(RegexRule):
    """Assignments of a string literal to a credential-looking name, in any language or config format."""

    def __init__(self) -> None:
        super().__init__(
            id="SEC002",
            title="Possible hardcoded secret",
            severity=Severity.HIGH,
            category=S,
            pattern=r"""(?i)\b[\w.-]*(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)\b["']?\s*[:=]>?\s*["'][^"'\s]{6,}["']""",
            message="Credential-like value assigned a string literal. Load it from the environment or a secret manager.",
            unless=_PLACEHOLDER.pattern,
        )


# --------------------------------------------------------------------------- dangerous calls (regex, non-Python)

def _regex_rules() -> list[RegexRule]:
    return [
        RegexRule("SEC003", "Dynamic code execution", Severity.HIGH, S,
                  # Outside Python, a bare exec() is usually a *shell* call (JS child_process, PHP) and is SEC004.
                  r"(?<![\w.])eval\s*\(|new\s+Function\s*\(|instance_eval|class_eval",
                  "eval on dynamic input allows arbitrary code execution.", languages=NOT_PY),
        RegexRule("SEC004", "Shell command injection risk", Severity.HIGH, S,
                  r"""child_process.*\bexec(Sync)?\s*\(|(?<![\w.])exec(Sync)?\(\s*["'`][^"'`]*["'`]\s*\+"""
                  r"""|Runtime\.getRuntime\(\)\.exec|\bsystem\s*\(|\bshell_exec\s*\(|\bpassthru\s*\(|`[^`]*#\{""",
                  "Command built from strings and run through a shell. Use an argument list API.",
                  languages=NOT_PY),
        RegexRule("SEC005", "SQL built by string concatenation", Severity.HIGH, S,
                  # A quoted SQL string (same quote at both ends) followed by +, %, .format(, .. or PHP's ". $".
                  r"""(?i)(["'`])\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b(?:(?!\1).)*\1\s*(\+|%|\.format\(|\.\.|\.\s*\$)"""
                  # Python f-strings and JS template literals with interpolation.
                  r"""|\bf(["'])(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b(?:(?!\4).)*\{|`\s*(SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{""",
                  "SQL assembled from strings is injectable. Use parameterised queries.", skip_docs=True),
        RegexRule("SEC006", "Weak cryptography", Severity.MEDIUM, S,
                  r"""(?i)(hashlib\.(md5|sha1)\b|\bmd5\s*\(|\bsha1\s*\(|createHash\(\s*["'](md5|sha1)["']|getInstance\(\s*["'](MD5|SHA-?1|DES)\b|\bDES\.new\(|\bARC4\b|\bRC4\b|MODE_ECB|/ECB/|\bDigestUtils\.(md5|sha1))""",  # audit: ignore[SEC006]
                  "MD5/SHA-1/DES/RC4/ECB are broken for security purposes. Use SHA-256+, AES-GCM, bcrypt/argon2.", skip_docs=True),  # audit: ignore[SEC006]
        RegexRule("SEC007", "Insecure deserialization", Severity.HIGH, S,
                  r"""(\bpickle\.loads?\(|\bcPickle\.loads?\(|\bmarshal\.loads?\(|\bshelve\.open\(|\byaml\.load\((?![^)]*Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader)|\bjsonpickle\.decode\(|ObjectInputStream|\bunserialize\s*\(|\bMarshal\.load|BinaryFormatter)""",  # audit: ignore[SEC007]
                  "Deserializing untrusted data can execute code. Use a data-only format (JSON) or a safe loader.", skip_docs=True),
        RegexRule("SEC008", "TLS verification disabled", Severity.HIGH, S,
                  r"""(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|_create_unverified_context|CERT_NONE|check_hostname\s*=\s*False|curl\s+(-k|--insecure)\b)""",  # audit: ignore[SEC008]
                  "Disabling certificate verification enables man-in-the-middle attacks.", skip_docs=True),
    ]


# --------------------------------------------------------------------------- Python AST

class PythonDangerousCallRule(FileRule):
    """AST version of SEC003/SEC004 for Python: exact, so comments/strings never match."""

    id = "SEC003"
    title = "Dangerous call"
    severity = Severity.HIGH
    category = S
    languages = PY

    _SHELL_FUNCS = {"os.system", "os.popen", "commands.getoutput", "subprocess.getoutput", "subprocess.getstatusoutput"}

    def check(self, file: SourceFile) -> Iterator[Finding]:
        tree = file.python_ast
        if tree is None:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted_name(node.func)
            line = file.lines[node.lineno - 1] if node.lineno <= len(file.lines) else ""
            if name in {"eval", "exec"} and not _is_literal(node.args[:1]):
                yield self.finding(file.path, node.lineno, f"{name}() on non-literal input allows arbitrary code execution.", line)
            elif name in self._SHELL_FUNCS:
                yield Finding("SEC004", "Shell command injection risk", Severity.HIGH, S,
                              f"{name}() runs through a shell. Use subprocess.run([...]) with an argument list.",
                              file.path, node.lineno, line.strip())
            elif any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                yield Finding("SEC004", "Shell command injection risk", Severity.HIGH, S,
                              "subprocess call with shell=True. Pass an argument list and drop shell=True.",
                              file.path, node.lineno, line.strip())


def _is_literal(args: list[ast.expr]) -> bool:
    return bool(args) and isinstance(args[0], ast.Constant)


# --------------------------------------------------------------------------- repo-level

_SECRET_FILES = re.compile(r"(^|/)(\.env(\.[\w-]+)?|id_rsa|id_dsa|id_ecdsa|id_ed25519|[^/]+\.(pem|key|p12|pfx|keystore|jks))$")
_SAFE_ENV = re.compile(r"\.(example|sample|template|dist|defaults?)$")


class CommittedSecretFileRule(RepoRule):
    id = "SEC009"
    title = "Secret file committed"
    severity = Severity.HIGH
    category = S

    def check(self, repo: Repo) -> Iterator[Finding]:
        for path in repo.all_paths:
            if _SECRET_FILES.search(path) and not _SAFE_ENV.search(path):
                yield self.finding(path, 0, f"'{path}' looks like an environment/key file. Remove it from version control and add it to .gitignore.")


# Tiny, offline advisory table: package -> (first fixed version, advisory hint).
# Deliberately small; the message points users at real tools (pip-audit, npm audit).
_PY_ADVISORIES: dict[str, tuple[str, str]] = {
    "requests": ("2.31.0", "CVE-2023-32681 proxy credential leak"),
    "urllib3": ("1.26.18", "CVE-2023-45803 / CVE-2023-43804"),
    "pyyaml": ("5.4", "CVE-2020-14343 arbitrary code execution in full_load"),
    "jinja2": ("3.1.3", "CVE-2024-22195 XSS"),
    "django": ("3.2.25", "multiple SQL injection / DoS advisories"),
    "flask": ("2.2.5", "CVE-2023-30861 session cookie disclosure"),
    "pillow": ("10.0.1", "CVE-2023-4863 libwebp heap overflow"),
    "cryptography": ("41.0.4", "multiple OpenSSL advisories"),
    "werkzeug": ("2.3.8", "CVE-2023-46136 DoS"),
}
_NPM_ADVISORIES: dict[str, tuple[str, str]] = {
    "lodash": ("4.17.21", "CVE-2021-23337 command injection"),
    "minimist": ("1.2.6", "CVE-2021-44906 prototype pollution"),
    "axios": ("1.6.0", "CVE-2023-45857 CSRF token leak"),
    "node-fetch": ("2.6.7", "CVE-2022-0235 header leak"),
    "jsonwebtoken": ("9.0.0", "CVE-2022-23529 / 23539 / 23540"),
    "express": ("4.19.2", "CVE-2024-29041 open redirect"),
    "moment": ("2.29.4", "CVE-2022-31129 ReDoS"),
}


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


class VulnerableDependencyRule(RepoRule):
    id = "SEC010"
    title = "Vulnerable or unpinned dependency"
    severity = Severity.MEDIUM
    category = S

    def check(self, repo: Repo) -> Iterator[Finding]:
        for f in repo.files:
            if re.search(r"(^|/)requirements[\w.-]*\.txt$", f.path):
                yield from self._requirements(f)
            elif f.name == "package.json":
                yield from self._package_json(f)

    def _requirements(self, f: SourceFile) -> Iterator[Finding]:
        for lineno, raw in enumerate(f.lines, start=1):
            line = raw.split("#", 1)[0].strip()
            m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|~=|<=)?\s*([\w.]+)?", line)
            if not m or line.startswith("-"):
                continue
            name = re.sub(r"\[.*\]", "", m.group(1)).lower()
            op, version = m.group(2), m.group(3)
            yield from self._evaluate(f.path, lineno, raw, name, op, version, _PY_ADVISORIES, "pip-audit")

    def _package_json(self, f: SourceFile) -> Iterator[Finding]:
        try:
            data = json.loads(f.text)
        except json.JSONDecodeError:
            return
        for section in ("dependencies", "devDependencies"):
            for name, spec in (data.get(section) or {}).items():
                lineno = next((i for i, ln in enumerate(f.lines, 1) if f'"{name}"' in ln), 0)
                op = None if spec in {"*", "latest", ""} else "=="
                version = spec.lstrip("^~>=< ") or None
                yield from self._evaluate(f.path, lineno, f'"{name}": "{spec}"', name.lower(), op, version, _NPM_ADVISORIES, "npm audit")

    def _evaluate(self, path: str, lineno: int, snippet: str, name: str, op: str | None,
                  version: str | None, table: dict[str, tuple[str, str]], tool: str) -> Iterator[Finding]:
        if not op or not version:
            yield self.finding(path, lineno, f"'{name}' is unpinned; builds are not reproducible and may pull a vulnerable release.",
                               snippet, severity=Severity.LOW)
        elif name in table and _version_tuple(version) < _version_tuple(table[name][0]):
            fixed, hint = table[name]
            yield self.finding(path, lineno, f"{name} {version} is below {fixed} ({hint}). Upgrade and run `{tool}` for a full check.",
                               snippet, severity=Severity.HIGH)


def rules() -> list[Rule]:
    return [KnownTokenRule(), SecretAssignmentRule(), *_regex_rules(), PythonDangerousCallRule(),
            CommittedSecretFileRule(), VulnerableDependencyRule()]
