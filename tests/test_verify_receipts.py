"""Unit tests for scripts/verify_receipts.py. Standard library only: python -m unittest discover -s tests"""
import contextlib
import hashlib
import http.server
import io
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import verify_receipts as vr  # noqa: E402

PY = shlex.quote(sys.executable.replace("\\", "/"))


def run_main(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = vr.main(args)
    return rc, buf.getvalue()


def check(spec, **kw):
    return vr.check(vr.parse_spec(spec), **kw)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/ok"):
            body = b"version 2.1.0 ready"
            self.send_response(200)
        elif self.path.startswith("/to-ftp"):
            self.send_response(302)
            self.send_header("Location", "ftp://127.0.0.1/x")
            self.end_headers()
            return
        elif self.path.startswith("/moved"):
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        else:
            body = b"maintenance"
            self.send_response(503)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ParseTests(unittest.TestCase):
    def test_kind_target_options(self):
        r = vr.parse_spec("http:https://example.test/a?x=1 | status=200,204 | contains=ok | via=probe")
        self.assertEqual(r.kind, "http")
        self.assertEqual(r.target, "https://example.test/a?x=1")
        self.assertEqual(r.options, {"status": "200,204", "contains": "ok", "via": "probe"})

    def test_shell_pipe_is_not_an_option_separator(self):
        r = vr.parse_spec("sh:printf abc | grep -q b | timeout=5")
        self.assertEqual(r.target, "printf abc | grep -q b")
        self.assertEqual(r.options, {"timeout": "5"})

    def test_unknown_kind_rejected(self):
        with self.assertRaises(vr.SpecError):
            vr.parse_spec("ssh:host uptime")

    def test_bad_proves_rejected(self):
        with self.assertRaises(vr.SpecError):
            vr.parse_spec("file:a | proves=vibes")

    def test_instrument_defaults_and_override(self):
        self.assertEqual(vr.parse_spec("cmd:FOO=1 /usr/bin/kubectl get pods").instrument(), "kubectl")
        self.assertEqual(vr.parse_spec("http:https://a.example.test/x").instrument(), "http:a.example.test")
        self.assertEqual(vr.parse_spec("file:x").instrument(), "filesystem")
        self.assertEqual(vr.parse_spec("commit:abcdef1").instrument(), "git")
        self.assertEqual(vr.parse_spec("cmd:curl -s x | via=status-page").instrument(), "status-page")


class CmdTests(unittest.TestCase):
    def test_exit_zero_passes(self):
        ok, _ = check("cmd:%s -c \"import sys; sys.exit(0)\"" % PY)
        self.assertTrue(ok)

    def test_nonzero_fails(self):
        ok, msg = check("cmd:%s -c \"import sys; sys.exit(3)\"" % PY)
        self.assertFalse(ok)
        self.assertIn("exit 3", msg)

    def test_expected_rc(self):
        ok, _ = check("cmd:%s -c \"import sys; sys.exit(3)\" | rc=3" % PY)
        self.assertTrue(ok)

    def test_contains(self):
        self.assertTrue(check("cmd:%s -c \"print('v2.1.0')\" | contains=v2.1.0" % PY)[0])
        ok, msg = check("cmd:%s -c \"print('v2.0.9')\" | contains=v2.1.0" % PY)
        self.assertFalse(ok)
        self.assertIn("does not contain", msg)

    def test_no_shell_for_cmd(self):
        # With no shell, ';' and the rest are plain arguments to python, not a second command.
        ok, _ = check("cmd:%s -c \"import sys; sys.exit(0)\" ; exit 7" % PY)
        self.assertTrue(ok)

    def test_timeout_is_an_error_not_a_pass(self):
        ok, msg = check("cmd:%s -c \"import time; time.sleep(5)\" | timeout=0.5" % PY)
        self.assertFalse(ok)
        self.assertIn("proves nothing", msg)

    def test_missing_binary_is_an_error(self):
        ok, msg = check("cmd:definitely-not-a-real-binary-xyz --version")
        self.assertFalse(ok)
        self.assertIn("proves nothing", msg)

    def test_sh_refused_without_flag(self):
        ok, msg = check("sh:exit 0")
        self.assertFalse(ok)
        self.assertIn("--allow-shell", msg)

    def test_sh_with_flag(self):
        self.assertTrue(check("sh:exit 0", allow_shell=True)[0])
        self.assertFalse(check("sh:exit 4", allow_shell=True)[0])

    def test_stdout_is_never_printed(self):
        # the spec only holds the pieces; the joined marker exists only in the command's stdout
        rc, out = run_main(["cmd:%s -c \"print('SENSITIVE' + '-OUTPUT-' + str(6*7))\"" % PY])
        self.assertEqual(rc, 0)
        self.assertNotIn("SENSITIVE-OUTPUT-42", out)
        self.assertIn("PASS", out)


class FileTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "a.txt")
        with open(self.p, "wb") as fh:
            fh.write(b"hello\n")
        self.sha = hashlib.sha256(b"hello\n").hexdigest()

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_exists(self):
        self.assertTrue(check("file:" + self.p)[0])
        self.assertFalse(check("file:" + self.p + ".missing")[0])
        self.assertFalse(check("file:" + self.d)[0])  # a directory is not a file

    def test_dir(self):
        self.assertTrue(check("dir:" + self.d)[0])
        self.assertFalse(check("dir:" + self.p)[0])

    def test_hash(self):
        self.assertTrue(check("file:%s | sha256=%s" % (self.p, self.sha))[0])
        ok, msg = check("file:%s | sha256=%s" % (self.p, "0" * 64))
        self.assertFalse(ok)
        self.assertIn("sha256 is", msg)

    def test_bad_hash_spec(self):
        ok, msg = check("file:%s | sha256=xyz" % self.p)
        self.assertFalse(ok)
        self.assertIn("bad receipt", msg)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_2xx(self):
        self.assertTrue(check("http:%s/ok" % self.base)[0])

    def test_503_fails(self):
        ok, msg = check("http:%s/down" % self.base)
        self.assertFalse(ok)
        self.assertIn("HTTP 503", msg)

    def test_expected_status(self):
        self.assertTrue(check("http:%s/down | status=503" % self.base)[0])

    def test_redirect_followed(self):
        self.assertTrue(check("http:%s/moved | status=200 | contains=2.1.0" % self.base)[0])

    def test_redirect_to_other_scheme_refused(self):
        ok, msg = check("http:%s/to-ftp" % self.base)
        self.assertFalse(ok)
        self.assertIn("non-http(s)", msg)
        self.assertIn("proves nothing", msg)

    def test_contains(self):
        ok, msg = check("http:%s/ok | contains=3.0.0" % self.base)
        self.assertFalse(ok)
        self.assertIn("does not contain", msg)

    def test_connection_refused_is_error(self):
        s = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        port = s.server_address[1]
        s.server_close()
        ok, msg = check("http:http://127.0.0.1:%d/ok | timeout=3" % port)
        self.assertFalse(ok)
        self.assertIn("proves nothing", msg)

    def test_non_http_scheme(self):
        ok, msg = check("http:file:///etc/hosts")
        self.assertFalse(ok)
        self.assertIn("only http", msg)


@unittest.skipIf(shutil.which("git") is None, "git not installed")
class CommitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()

        def git(*a):
            return subprocess.run(["git", "-C", cls.d, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                   "-c", "commit.gpgsign=false"] + list(a),
                                  check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
        git("init", "-q")
        git("checkout", "-q", "-b", "main")
        with open(os.path.join(cls.d, "app.py"), "w") as fh:
            fh.write("print(1)\n")
        git("add", "app.py")
        git("commit", "-q", "-m", "one")
        cls.h1 = git("rev-parse", "HEAD")
        git("checkout", "-q", "-b", "side")
        with open(os.path.join(cls.d, "other.txt"), "w") as fh:
            fh.write("x\n")
        git("add", "other.txt")
        git("commit", "-q", "-m", "two")
        cls.h2 = git("rev-parse", "HEAD")
        # a dotfile commit on main, then a non-conflicting merge of side into main
        git("checkout", "-q", "main")
        with open(os.path.join(cls.d, ".gitignore"), "w") as fh:
            fh.write("*.pyc\n")
        git("add", ".gitignore")
        git("commit", "-q", "-m", "dotfile")
        cls.h3 = git("rev-parse", "HEAD")
        git("merge", "-q", "--no-ff", "--no-edit", "side")
        cls.merge = git("rev-parse", "HEAD")
        # a commit that exists only on side
        git("checkout", "-q", "side")
        with open(os.path.join(cls.d, "late.txt"), "w") as fh:
            fh.write("late\n")
        git("add", "late.txt")
        git("commit", "-q", "-m", "three")
        cls.h4 = git("rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_exists(self):
        self.assertTrue(check("commit:%s | repo=%s" % (self.h1[:10], self.d))[0])
        ok, msg = check("commit:%s | repo=%s" % ("deadbee", self.d))
        self.assertFalse(ok)
        self.assertIn("not found", msg)

    def test_path(self):
        self.assertTrue(check("commit:%s | repo=%s | path=app.py" % (self.h1, self.d))[0])  # root commit
        self.assertFalse(check("commit:%s | repo=%s | path=other.txt" % (self.h1, self.d))[0])

    def test_dotfile_path(self):
        self.assertTrue(check("commit:%s | repo=%s | path=.gitignore" % (self.h3, self.d))[0])
        self.assertTrue(check("commit:%s | repo=%s | path=./.gitignore" % (self.h3, self.d))[0])

    def test_merge_commit_path(self):
        # a merge brings other.txt into main; the receipt should see that
        ok, msg = check("commit:%s | repo=%s | path=other.txt | branch=main" % (self.merge, self.d))
        self.assertTrue(ok, msg)
        self.assertFalse(check("commit:%s | repo=%s | path=app.py" % (self.merge, self.d))[0])

    def test_branch(self):
        self.assertTrue(check("commit:%s | repo=%s | branch=main" % (self.h1, self.d))[0])
        self.assertTrue(check("commit:%s | repo=%s | branch=main" % (self.h2, self.d))[0])  # merged
        ok, msg = check("commit:%s | repo=%s | branch=main" % (self.h4, self.d))
        self.assertFalse(ok)
        self.assertIn("not on main", msg)

    def test_unknown_branch_is_error(self):
        ok, msg = check("commit:%s | repo=%s | branch=nope" % (self.h1, self.d))
        self.assertFalse(ok)
        self.assertIn("proves nothing", msg)

    def test_option_injection_rejected(self):
        ok, msg = check("commit:--output=x | repo=%s" % self.d)
        self.assertFalse(ok)
        self.assertIn("bad receipt", msg)
        ok, msg = check("commit:%s | repo=%s | branch=--all" % (self.h1, self.d))
        self.assertFalse(ok)
        self.assertIn("bad receipt", msg)


class RedactionTests(unittest.TestCase):
    def test_redact_patterns(self):
        cases = {
            "https://alice:hunter2@host.example.test/x": "hunter2",
            "https://host.example.test/x?token=abc123&q=1": "abc123",
            "https://host.example.test/x?api_key=k3y": "k3y",
            "--password=s3cret": "s3cret",
            "--api-key s3cret2": "s3cret2",
            "DB_PASSWORD=pw9 run": "pw9",
            "Authorization: Bearer eyJabc.def": "eyJabc",
            "ghp_abcdefghijklmnopqrstuvwxyz0123": "ghp_abcdefghijklmnop",
        }
        for text, secret in cases.items():
            self.assertNotIn(secret, vr.redact(text), text)

    def test_main_output_has_no_secrets(self):
        rc, out = run_main([
            "http:https://u:p4ssw0rd@127.0.0.1:9/?token=abc999 | timeout=2",
            "cmd:definitely-not-a-real-binary-xyz --password=x7x7x7 --token tkn888",
        ])
        self.assertEqual(rc, 1)
        for secret in ("p4ssw0rd", "abc999", "x7x7x7", "tkn888"):
            self.assertNotIn(secret, out)
        self.assertEqual(out.count("FAIL"), 2)


class SaidAndJudgeTests(unittest.TestCase):
    def test_said_is_a_claim_not_a_check(self):
        ok, msg = check("said:worker-2 reported RESULT=ok")
        self.assertIsNone(ok)
        self.assertIn("not evidence", msg)

    def test_judge_only_self_reports(self):
        proven, reason = vr.judge([(vr.parse_spec("said:worker says ok"), None, "")], 1)
        self.assertFalse(proven)
        self.assertIn("only self-reports", reason)

    def test_said_does_not_block_a_real_receipt(self):
        res = [(vr.parse_spec("said:worker says ok"), None, ""), (vr.parse_spec("cmd:true"), True, "")]
        self.assertEqual(vr.judge(res, 1)[0], True)

    def test_said_does_not_count_as_an_instrument(self):
        res = [(vr.parse_spec("said:worker says ok"), None, ""), (vr.parse_spec("cmd:true"), True, "")]
        self.assertFalse(vr.judge(res, 2)[0])

    def test_said_printed_as_claim(self):
        rc, out = run_main(["said:worker says ok"])
        self.assertEqual(rc, 1)
        self.assertIn("CLAIM  [1] said:", out)
        self.assertNotIn("PASS", out)

    def _res(self, *specs_ok):
        return [(vr.parse_spec(s), ok, "") for s, ok in specs_ok]

    def test_judge_no_receipts(self):
        self.assertEqual(vr.judge([], 1), (False, "no receipts"))

    def test_judge_config_only(self):
        proven, reason = vr.judge(self._res(("file:app.yaml | proves=config", True)), 1)
        self.assertFalse(proven)
        self.assertIn("config check is not a behaviour check", reason)

    def test_judge_same_instrument_counts_once(self):
        res = self._res(("cmd:curl -sf https://a.example.test/health", True),
                        ("cmd:curl -sf https://a.example.test/version", True))
        self.assertTrue(vr.judge(res, 1)[0])
        proven, reason = vr.judge(res, 2)
        self.assertFalse(proven)
        self.assertIn("1 instrument", reason)

    def test_judge_two_instruments(self):
        res = self._res(("cmd:curl -sf https://a.example.test/health", True),
                        ("cmd:kubectl get pods", True))
        self.assertTrue(vr.judge(res, 2)[0])

    def test_config_instrument_does_not_count_toward_min(self):
        res = self._res(("http:https://a.example.test/version", True),
                        ("cmd:kubectl get deploy web | proves=config", True))
        proven, reason = vr.judge(res, 2)
        self.assertFalse(proven)
        self.assertIn("1 behaviour receipt(s) through 1 instrument(s)", reason)

    def test_judge_any_failure(self):
        res = self._res(("cmd:true", True), ("cmd:false", False))
        proven, reason = vr.judge(res, 1)
        self.assertFalse(proven)
        self.assertIn("receipt 2 failed", reason)
        res = self._res(("cmd:false", False), ("cmd:false", False))
        self.assertIn("receipts 1, 2 failed", vr.judge(res, 1)[1])


@unittest.skipIf(shutil.which("git") is None, "git not installed")
class BaselineTests(unittest.TestCase):
    """Fail before, pass after: HEAD~1 has a broken add(), HEAD fixes it."""

    @classmethod
    def setUpClass(cls):
        cls.d = os.path.realpath(tempfile.mkdtemp())

        def git(*a):
            return subprocess.run(["git", "-C", cls.d, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                   "-c", "commit.gpgsign=false"] + list(a),
                                  check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
        cls.git = staticmethod(git)

        def write(name, text):
            os.makedirs(os.path.dirname(os.path.join(cls.d, name)), exist_ok=True)
            with open(os.path.join(cls.d, name), "w", newline="\n") as fh:  # LF on Windows too, for sha256=
                fh.write(text)
        git("init", "-q")
        git("config", "core.autocrlf", "false")
        write("calc.py", "def add(a, b):\n    return a - b\n")
        write("test_add.py", "import calc, sys\nsys.exit(0 if calc.add(2, 2) == 4 else 1)\n")
        # deliberately vacuous: passes whatever calc.py does
        write("test_vacuous.py", "import sys\nsys.exit(0)\n")
        write("sub/run.py", "import os, sys\nsys.path.insert(0, '..')\nimport calc\n"
                            "sys.exit(0 if calc.add(1, 2) == 3 else 1)\n")
        git("add", ".")
        git("commit", "-q", "-m", "broken add")
        cls.old_sha = hashlib.sha256(b"def add(a, b):\n    return a - b\n").hexdigest()
        write("calc.py", "def add(a, b):\n    return a + b\n")
        cls.new_sha = hashlib.sha256(b"def add(a, b):\n    return a + b\n").hexdigest()
        git("commit", "-q", "-am", "fix add")
        cls.head = git("rev-parse", "HEAD")
        # a test written in the same change, not committed, so it is absent at every ref
        write("test_new.py", "import calc, sys\nsys.exit(0 if calc.add(5, 5) == 10 else 1)\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def setUp(self):
        self.old_cwd = os.getcwd()
        os.chdir(self.d)

    def tearDown(self):
        os.chdir(self.old_cwd)

    def baseline(self, spec, **kw):
        r = vr.parse_spec(spec)
        ok, _ = vr.check(r, **kw)
        return vr.check_baseline(r, ok, **kw)

    def cmd(self, script, *opts):
        return " | ".join(["cmd:%s %s" % (PY, script)] + list(opts))

    def test_proven_fails_before_passes_after(self):
        verdict, msg = self.baseline(self.cmd("test_add.py", "baseline=HEAD~1"))
        self.assertEqual(verdict, vr.PROVEN, msg)
        self.assertIn("fails before the change, passes after", msg)

    def test_vacuous_passes_before_and_after(self):
        verdict, msg = self.baseline(self.cmd("test_vacuous.py", "baseline=HEAD~1"))
        self.assertEqual(verdict, vr.VACUOUS, msg)
        self.assertIn("not evidence", msg)

    def test_broken_fails_after(self):
        verdict, msg = self.baseline(self.cmd("-c \"import sys; sys.exit(1)\"", "baseline=HEAD~1"))
        self.assertEqual(verdict, vr.BROKEN)
        self.assertIn("fails after the change", msg)

    def test_na_for_kinds_without_pre_change_state(self):
        for spec in ("commit:%s | baseline=HEAD~1" % self.head, "said:worker says ok | baseline=HEAD~1"):
            r = vr.parse_spec(spec)
            self.assertEqual(vr.check_baseline(r, True)[0], vr.NA, spec)
        r = vr.parse_spec("http:https://example.test/ | baseline=HEAD~1")
        verdict, msg = vr.check_baseline(r, True)
        self.assertEqual(verdict, vr.NA)
        self.assertIn("no pre-change state", msg)

    def test_unresolvable_ref_is_na_not_proven(self):
        verdict, msg = self.baseline(self.cmd("test_add.py", "baseline=no-such-ref"))
        self.assertEqual(verdict, vr.NA)
        self.assertIn("proves nothing", msg)

    def test_bad_ref_rejected(self):
        verdict, msg = self.baseline(self.cmd("test_add.py", "baseline=--all"))
        self.assertEqual(verdict, vr.NA)
        self.assertIn("bad receipt", msg)

    def test_new_check_without_keep_is_na(self):
        # absent at HEAD~1, the new test would fail there only because it does not exist
        verdict, msg = self.baseline(self.cmd("test_new.py", "baseline=HEAD~1"))
        self.assertEqual(verdict, vr.NA)
        self.assertIn("keep=test_new.py", msg)

    def test_keep_runs_new_check_against_old_code(self):
        verdict, msg = self.baseline(self.cmd("test_new.py", "baseline=HEAD~1", "keep=test_new.py"))
        self.assertEqual(verdict, vr.PROVEN, msg)
        # kept into a baseline where the code is already fixed: vacuous
        verdict, msg = self.baseline(self.cmd("test_new.py", "baseline=HEAD", "keep=test_new.py"))
        self.assertEqual(verdict, vr.VACUOUS, msg)

    def test_absolute_path_into_repo_is_na(self):
        verdict, msg = self.baseline(self.cmd(os.path.join(self.d, "test_add.py").replace("\\", "/"),
                                              "baseline=HEAD~1"))
        self.assertEqual(verdict, vr.NA)
        self.assertIn("absolute path", msg)

    def test_subdirectory_maps_into_worktree(self):
        os.chdir(os.path.join(self.d, "sub"))
        verdict, msg = self.baseline(self.cmd("run.py", "baseline=HEAD~1"))
        self.assertEqual(verdict, vr.PROVEN, msg)

    def test_sh_baseline(self):
        spec = "sh:%s test_vacuous.py | baseline=HEAD~1" % PY
        self.assertEqual(self.baseline(spec, allow_shell=True)[0], vr.VACUOUS)

    def test_file_against_git_ref(self):
        self.assertEqual(self.baseline("file:calc.py | sha256=%s | baseline=HEAD~1" % self.new_sha)[0], vr.PROVEN)
        # existence alone held before the change
        self.assertEqual(self.baseline("file:calc.py | baseline=HEAD~1")[0], vr.VACUOUS)
        self.assertEqual(self.baseline("dir:sub | baseline=HEAD~1")[0], vr.VACUOUS)

    def test_file_outside_repo_is_na(self):
        outside = tempfile.mkdtemp()
        try:
            verdict, msg = self.baseline("dir:%s | baseline=HEAD~1" % outside.replace("\\", "/"))
        finally:
            shutil.rmtree(outside)
        self.assertEqual(verdict, vr.NA)
        self.assertIn("outside the repository", msg)

    def test_before_recorded_state(self):
        self.assertEqual(self.baseline("file:test_new.py | before=absent")[0], vr.PROVEN)
        self.assertEqual(self.baseline("file:calc.py | before=present")[0], vr.VACUOUS)
        self.assertEqual(self.baseline("file:calc.py | sha256=%s | before=%s" % (self.new_sha, self.old_sha))[0],
                         vr.PROVEN)
        self.assertEqual(self.baseline("file:calc.py | sha256=%s | before=%s" % (self.new_sha, self.new_sha))[0],
                         vr.VACUOUS)
        self.assertEqual(self.baseline("dir:sub | before=present")[0], vr.VACUOUS)
        self.assertEqual(self.baseline("dir:sub | before=absent")[0], vr.PROVEN)

    def test_bad_before_is_na(self):
        for spec in ("file:calc.py | before=sometimes", "dir:sub | before=%s" % self.old_sha,
                     "file:calc.py | sha256=%s | before=present" % self.new_sha,
                     self.cmd("test_add.py", "before=absent")):
            verdict, msg = self.baseline(spec)
            self.assertEqual(verdict, vr.NA, spec)
            self.assertIn("bad receipt", msg)

    def test_parse_rules(self):
        with self.assertRaises(vr.SpecError):
            vr.parse_spec("file:calc.py | baseline=HEAD~1 | before=absent")
        with self.assertRaises(vr.SpecError):
            vr.parse_spec("cmd:true | keep=test_new.py")

    def test_worktree_removed(self):
        self.baseline(self.cmd("test_add.py", "baseline=HEAD~1"))
        self.assertEqual(len(self.git("worktree", "list").splitlines()), 1)

    def test_main_prints_vacuous_and_summary(self):
        rc, out = run_main([self.cmd("test_add.py", "baseline=HEAD~1"), self.cmd("test_vacuous.py", "baseline=HEAD~1")])
        self.assertEqual(rc, 0)  # the PROVEN receipt still proves the claim; the vacuous one is not counted
        self.assertIn("VACUOUS  [2]", out)
        self.assertIn("receipt 2 VACUOUS, not counted", out)
        self.assertIn("baseline: 1 proven, 1 vacuous, 0 broken, 0 n/a", out)

    def test_main_vacuous_only_is_unproven(self):
        rc, out = run_main([self.cmd("test_vacuous.py", "baseline=HEAD~1")])
        self.assertEqual(rc, 1)
        self.assertIn("only VACUOUS behaviour receipts passed", out)

    def test_main_require_baseline(self):
        add, vac = self.cmd("test_add.py", "baseline=HEAD~1"), self.cmd("test_vacuous.py", "baseline=HEAD~1")
        self.assertEqual(run_main(["--require-baseline", add])[0], 0)
        rc, out = run_main(["--require-baseline", add, vac])
        self.assertEqual(rc, 1)
        self.assertIn("receipt 2 VACUOUS", out)
        # a receipt with no baseline, or an N/A one, is never upgraded to a baseline
        rc, out = run_main(["--require-baseline", self.cmd("test_add.py"), self.cmd("test_new.py", "baseline=HEAD~1")])
        self.assertEqual(rc, 1)
        self.assertIn("N/A", out)
        self.assertIn("no behaviour receipt was shown to fail before the change", out)

    def test_ledger_without_baselines_is_unchanged(self):
        rc, out = run_main([self.cmd("test_add.py")])
        self.assertEqual(rc, 0)
        self.assertNotIn("baseline", out)


class BaselineJudgeTests(unittest.TestCase):
    def _res(self, *rows):
        return [(vr.parse_spec(s), ok, "", v) for s, ok, v in rows]

    def test_vacuous_is_not_evidence(self):
        proven, reason = vr.judge(self._res(("cmd:true", True, vr.VACUOUS)), 1)
        self.assertFalse(proven)
        self.assertIn("only VACUOUS", reason)

    def test_vacuous_does_not_count_as_an_instrument(self):
        res = self._res(("cmd:true", True, vr.PROVEN), ("cmd:kubectl get pods", True, vr.VACUOUS))
        self.assertTrue(vr.judge(res, 1)[0])
        self.assertFalse(vr.judge(res, 2)[0])

    def test_require_baseline(self):
        self.assertTrue(vr.judge(self._res(("cmd:true", True, vr.PROVEN)), 1, True)[0])
        for v in (None, vr.NA):
            proven, reason = vr.judge(self._res(("http:https://a.example.test/", True, v)), 1, True)
            self.assertFalse(proven)
            self.assertIn("--require-baseline", reason)
        res = self._res(("cmd:true", True, vr.PROVEN), ("cmd:other", True, vr.VACUOUS))
        self.assertIn("receipt 2 VACUOUS", vr.judge(res, 1, True)[1])

    def test_config_baseline_does_not_satisfy_require(self):
        res = self._res(("file:app.yaml | proves=config", True, vr.PROVEN), ("http:https://a.example.test/", True, vr.NA))
        self.assertFalse(vr.judge(res, 1, True)[0])

    def test_broken_is_a_failure(self):
        proven, reason = vr.judge(self._res(("cmd:true", False, vr.BROKEN)), 1)
        self.assertFalse(proven)
        self.assertIn("receipt 1 failed", reason)


LEDGER = """# Ledger: release 2.1.0

- [x] 1. Build artifact
  - receipt: `file:{art} | sha256={sha}`
- [x] 2. Config points at the new artifact
  - receipt: `file:{art} | proves=config`
- [x] 3. Worker deployed it
  - receipt: `said:worker reported RESULT=ok`
- [ ] 4. Announce
"""


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.art = os.path.join(self.d, "app.tar").replace("\\", "/")
        with open(self.art, "wb") as fh:
            fh.write(b"artifact")
        self.ledger = os.path.join(self.d, "receipts.md")
        with open(self.ledger, "w") as fh:
            fh.write(LEDGER.format(art=self.art, sha=hashlib.sha256(b"artifact").hexdigest()))

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_parse(self):
        with open(self.ledger) as fh:
            steps = vr.parse_ledger(fh.read())
        self.assertEqual([s.number for s in steps], ["1", "2", "3", "4"])
        self.assertEqual([s.done for s in steps], [True, True, True, False])
        self.assertEqual([len(s.receipts) for s in steps], [1, 1, 1, 0])

    def test_verdicts(self):
        rc, out = run_main(["--ledger", self.ledger])
        self.assertEqual(rc, 1)
        self.assertIn("-> PROVEN", out)
        self.assertIn("config check is not a behaviour check", out)
        self.assertIn("only self-reports", out)
        self.assertIn("summary: 2 pass, 0 fail; 1 of 3 done step(s) proven", out)

    def test_list_does_not_run(self):
        rc, out = run_main(["--ledger", self.ledger, "--list"])
        self.assertEqual(rc, 0)
        self.assertNotIn("PASS", out)

    def test_reopen_strikes_and_never_deletes(self):
        with open(self.ledger) as fh:
            before = fh.read().splitlines()
        rc, out = run_main(["--ledger", self.ledger, "--reopen"])
        self.assertEqual(rc, 1)
        with open(self.ledger) as fh:
            after = fh.read()
        lines = after.splitlines()
        self.assertEqual(len(lines), len(before) + 2)
        self.assertIn("- ~~[x] 2. Config points at the new artifact~~ reopened", after)
        self.assertIn("- [ ] 2. Config points at the new artifact", after)
        self.assertIn("- ~~[x] 3. Worker deployed it~~ reopened", after)
        self.assertIn("- [x] 1. Build artifact", after)
        # every original receipt line is still there
        for line in before:
            if "receipt:" in line:
                self.assertIn(line, lines)
        # running again changes nothing: reopened steps are open, not done
        rc, _ = run_main(["--ledger", self.ledger, "--reopen"])
        self.assertEqual(rc, 0)
        with open(self.ledger) as fh:
            self.assertEqual(fh.read(), after)


TARGET_LEDGER = """# Ledger: deploy shop 3.1.0

- [x] 1. shop runs 3.1.0 in production
  - target: shop
  - receipt: `cmd:{py} -c "import sys; print(sys.argv[1] + ': running 3.1.0')" shop-canary | contains=running 3.1.0`
- [x] 2. shop runs 3.1.0 in production
  - target: shop
  - receipt: `cmd:{py} -c "import sys; print(sys.argv[1] + ': running 3.1.0')" shop | contains=running 3.1.0`
- [x] 3. accounts backup is verified
  - target: {dump} | needs=sha256
  - receipt: `file:{dump}`
  - receipt: `dir:{bdir}`
- [x] 4. accounts backup is verified
  - target: {dump} | needs=sha256
  - receipt: `file:{dump} | sha256={sha}`
"""


class TargetTests(unittest.TestCase):
    """A receipt counts for a claim only when it checks the object the claim names."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.bdir = os.path.join(self.d, "backups").replace("\\", "/")
        os.mkdir(self.bdir)
        self.dump = self.bdir + "/accounts.dump"
        with open(self.dump, "wb") as fh:
            fh.write(b"rows")
        self.sha = hashlib.sha256(b"rows").hexdigest()

    def tearDown(self):
        shutil.rmtree(self.d)

    def _res(self, *specs):
        return [(vr.parse_spec(s), True, "ok", None) for s in specs]

    def test_receipt_target_must_be_what_the_check_reads(self):
        ok, msg = check("cmd:%s -c pass web-canary | target=web" % PY)
        self.assertFalse(ok)
        self.assertIn("not what this check reads", msg)
        self.assertTrue(check("cmd:%s -c pass web | target=web" % PY)[0])

    def test_receipt_target_on_paths_and_urls(self):
        self.assertTrue(check("file:%s | target=accounts.dump" % self.dump)[0])
        self.assertFalse(check("file:%s | target=orders.dump" % self.dump)[0])
        r = vr.parse_spec("http:https://shop.example.test/version | target=shop.example.test")
        self.assertTrue(vr.reads(r, "shop.example.test"))
        self.assertFalse(vr.reads(r, "shop-canary.example.test"))

    def test_word_match_is_whole_word(self):
        r = vr.parse_spec("cmd:svcctl status web-canary")
        self.assertFalse(vr.about(r, "web"))
        self.assertTrue(vr.about(r, "web-canary"))
        self.assertTrue(vr.about(vr.parse_spec("cmd:svcctl status --service=web"), "web"))

    def test_judge_counts_only_receipts_about_the_claim(self):
        claim = vr.Claim("web")
        proven, reason = vr.judge(self._res("cmd:svcctl status web-canary"), 1, claim=claim)
        self.assertFalse(proven)
        self.assertIn("claimed target web", reason)
        proven, reason = vr.judge(self._res("cmd:svcctl status web-canary", "cmd:svcctl status web"), 1, claim=claim)
        self.assertTrue(proven)
        self.assertIn("1 receipt(s) about another object, not counted", reason)
        # min-instruments counts only receipts about the claim
        res = self._res("cmd:svcctl status web", "http:https://web-canary.example.test/")
        self.assertFalse(vr.judge(res, 2, claim=claim)[0])

    def test_explicit_target_overrides_the_words(self):
        claim = vr.Claim("web")
        self.assertFalse(vr.judge(self._res("cmd:svcctl status web | target=web-canary"), 1, claim=claim)[0])

    def test_listing_does_not_satisfy_a_checksum_claim(self):
        claim = vr.Claim(self.dump, "sha256")
        proven, reason = vr.judge(self._res("file:%s" % self.dump, "cmd:ls -l %s" % self.dump), 1, claim=claim)
        self.assertFalse(proven)
        self.assertIn("needs the sha256", reason)
        self.assertTrue(vr.judge(self._res("file:%s | sha256=%s" % (self.dump, self.sha)), 1, claim=claim)[0])

    def test_sha256_only_on_file_receipts(self):
        for spec in ("cmd:ls -l backups/ | sha256=%s" % self.sha, "dir:backups | sha256=%s" % self.sha,
                     "http:https://a.example.test/f | sha256=%s" % self.sha):
            with self.assertRaises(vr.SpecError) as cm:
                vr.parse_spec(spec)
            self.assertIn("not a checksum", str(cm.exception))

    def test_no_claim_keeps_old_behaviour(self):
        self.assertTrue(vr.judge(self._res("cmd:svcctl status web-canary"), 1)[0])

    def test_parse_claim(self):
        c = vr.parse_claim("`backups/a.dump` | needs=sha256")
        self.assertEqual((c.name, c.needs), ("backups/a.dump", "sha256"))
        with self.assertRaises(vr.SpecError):
            vr.parse_claim("x | needs=md5")

    def test_ledger(self):
        ledger = os.path.join(self.d, "receipts.md")
        with open(ledger, "w") as fh:
            fh.write(TARGET_LEDGER.format(py=PY, dump=self.dump, bdir=self.bdir, sha=self.sha))
        rc, out = run_main(["--ledger", ledger])
        self.assertEqual(rc, 1)
        self.assertIn("summary: 5 pass, 0 fail; 2 of 4 done step(s) proven", out)
        self.assertIn("claimed target shop;", out)
        self.assertIn("needs the sha256", out)
        rc, out = run_main(["--ledger", ledger, "--list"])
        self.assertIn("target: shop", out)

    def test_command_line_target(self):
        spec = "cmd:%s -c pass shop-canary" % PY
        self.assertEqual(run_main([spec])[0], 0)
        rc, out = run_main(["--target", "shop", spec])
        self.assertEqual(rc, 1)
        self.assertIn("claimed target shop", out)
        self.assertEqual(run_main(["--target", "shop", "cmd:%s -c pass shop" % PY])[0], 0)
        self.assertEqual(run_main(["--target", "shop", "--ledger", "x.md"])[0], 2)


class UsageTests(unittest.TestCase):
    def test_no_args(self):
        self.assertEqual(run_main([])[0], 2)

    def test_both_modes(self):
        self.assertEqual(run_main(["--ledger", "x.md", "file:x"])[0], 2)

    def test_reopen_needs_ledger(self):
        self.assertEqual(run_main(["--reopen", "file:x"])[0], 2)

    def test_unknown_option(self):
        self.assertEqual(run_main(["--nope", "file:x"])[0], 2)

    def test_baseline_and_before_together_is_a_parse_error(self):
        self.assertEqual(run_main(["file:x | baseline=HEAD~1 | before=absent"])[0], 2)


if __name__ == "__main__":
    unittest.main()
