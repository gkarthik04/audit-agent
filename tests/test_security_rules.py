# audit: ignore-file -- these tests deliberately contain the patterns the rules detect.
import pytest

from audit_agent.models import Severity
from audit_agent.rules import security
from audit_agent.rules.security import (
    CommittedSecretFileRule,
    KnownTokenRule,
    PythonDangerousCallRule,
    SecretAssignmentRule,
    VulnerableDependencyRule,
)
from conftest import run_file_rule, run_repo_rule


def regex_rule(rule_id: str):
    return next(r for r in security.rules() if r.id == rule_id and hasattr(r, "pattern"))


# Test credentials are deliberately fake *and* unmistakable: the AWS-style id uses digits (0, 1, 8,
# 9) that real AWS key ids never contain, and the other values have low entropy. Our detector still
# flags them, but generic secret scanners (gitleaks) correctly do not.
FAKE_AWS_ID = "AKIA0189Q3EGUXNPLW7R"


class TestSecrets:
    def test_known_token_is_critical(self):
        hits = run_file_rule(KnownTokenRule(), "cfg.py", f'aws_id = "{FAKE_AWS_ID}"\n')
        assert [h.severity for h in hits] == [Severity.CRITICAL]

    def test_placeholder_token_is_ignored(self):
        documented_example = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documentation key, split so no scanner trips on this file
        assert run_file_rule(KnownTokenRule(), "cfg.py", f'aws_id = "{documented_example}"\n') == []

    @pytest.mark.parametrize("line", [
        'password = "hunter2hunter2"',
        "db_password: 'S3cr3t!!'",
        'const apiKey = "qwerty123qwerty123";',
        '"client_secret": "abcabcabcabc"',
    ])
    def test_secret_assignment(self, line):
        assert run_file_rule(SecretAssignmentRule(), "x.any", line) != []

    @pytest.mark.parametrize("line", [
        'password = os.environ["DB_PASSWORD"]',
        'api_key = "<your-api-key>"',
        'password = "changeme"',
        "PASSWORD_MIN_LENGTH = 8",
    ])
    def test_secret_assignment_ignores_non_secrets(self, line):
        assert run_file_rule(SecretAssignmentRule(), "x.py", line) == []


class TestDangerousCalls:
    def test_python_eval_on_variable(self):
        hits = run_file_rule(PythonDangerousCallRule(), "a.py", "eval(user_input)\n")
        assert [h.rule_id for h in hits] == ["SEC003"]

    def test_python_eval_on_literal_is_fine(self):
        assert run_file_rule(PythonDangerousCallRule(), "a.py", "eval('1 + 1')\n") == []

    def test_python_shell_true_and_os_system(self):
        code = """
        import os, subprocess
        subprocess.run(cmd, shell=True)
        os.system("ls " + d)
        subprocess.run(["ls", d])
        """
        hits = run_file_rule(PythonDangerousCallRule(), "a.py", code)
        assert [(h.rule_id, h.line) for h in hits] == [("SEC004", 2), ("SEC004", 3)]

    def test_python_rule_ignores_comments_and_strings(self):
        code = '# never call eval(x)\nmsg = "use shell=True carefully"\n'
        assert run_file_rule(PythonDangerousCallRule(), "a.py", code) == []

    def test_js_eval_and_exec_concat(self):
        code = "eval(req.body)\nexec('ls ' + dir, cb)\nregex.exec(s)\n"
        rule_ids = [h.rule_id for r in ("SEC003", "SEC004") for h in run_file_rule(regex_rule(r), "a.js", code)]
        assert rule_ids == ["SEC003", "SEC004"]


class TestSqlInjection:
    @pytest.mark.parametrize("line", [
        """cursor.execute("SELECT * FROM users WHERE id = '" + uid + "'")""",
        """db.query(f"DELETE FROM t WHERE id = {tid}")""",
        """q = "UPDATE t SET a = %s" % value""",
        "const q = `SELECT * FROM users WHERE name = ${name}`;",
        """$q = "SELECT * FROM users WHERE id = " . $id;""",
    ])
    def test_concatenated_sql(self, line):
        assert run_file_rule(regex_rule("SEC005"), "x.any", line) != []

    def test_parameterised_sql_is_fine(self):
        assert run_file_rule(regex_rule("SEC005"), "x.py", 'cur.execute("SELECT * FROM t WHERE id = ?", (uid,))') == []


@pytest.mark.parametrize("rule_id,line", [
    ("SEC006", "h = hashlib.md5(data)"),
    ("SEC006", "crypto.createHash('sha1')"),
    ("SEC007", "obj = pickle.loads(blob)"),
    ("SEC007", "cfg = yaml.load(f)"),
    ("SEC008", "requests.get(url, verify=False)"),
    ("SEC008", "{ rejectUnauthorized: false }"),
    ("SEC008", "TLSClientConfig: &tls.Config{InsecureSkipVerify: true}"),
])
def test_risky_patterns(rule_id, line):
    assert run_file_rule(regex_rule(rule_id), "x.any", line) != []


def test_yaml_safe_loader_is_fine():
    assert run_file_rule(regex_rule("SEC007"), "x.py", "yaml.load(f, Loader=yaml.SafeLoader)") == []


class TestRepoLevel:
    def test_committed_env_file(self):
        files = {".env": "A=1", ".env.example": "A=", "deploy/id_rsa": "x", "src/keys.py": ""}
        paths = [f.path for f in run_repo_rule(CommittedSecretFileRule(), files)]
        assert paths == [".env", "deploy/id_rsa"]

    def test_vulnerable_and_unpinned_python_deps(self):
        hits = run_repo_rule(VulnerableDependencyRule(), {"requirements.txt": "requests==2.20.0\nflask\nrequests-oauthlib==1.3.1\n"})
        assert [(h.line, h.severity) for h in hits] == [(1, Severity.HIGH), (2, Severity.LOW)]

    def test_vulnerable_npm_dep(self):
        pkg = '{"dependencies": {"lodash": "^4.17.15", "react": "18.2.0"}}'
        hits = run_repo_rule(VulnerableDependencyRule(), {"package.json": pkg})
        assert [h.severity for h in hits] == [Severity.HIGH]
