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


class UsageTests(unittest.TestCase):
    def test_no_args(self):
        self.assertEqual(run_main([])[0], 2)

    def test_missing_value_names_option(self):
        for option in ("--timeout", "--min-instruments", "--ledger"):
            rc, out = run_main([option])
            self.assertEqual(rc, 2)
            self.assertIn(option + " needs a value", out)

    def test_timeout_invalid_value_names_option(self):
        rc, out = run_main(["--timeout", "abc", "file:x"])
        self.assertEqual(rc, 2)
        self.assertIn("--timeout expects a number of seconds, got 'abc'", out)

    def test_min_instruments_invalid_value_names_option(self):
        rc, out = run_main(["--min-instruments", "x", "file:x"])
        self.assertEqual(rc, 2)
        self.assertIn("--min-instruments expects a whole number, got 'x'", out)

    def test_both_modes(self):
        self.assertEqual(run_main(["--ledger", "x.md", "file:x"])[0], 2)

    def test_reopen_needs_ledger(self):
        self.assertEqual(run_main(["--reopen", "file:x"])[0], 2)

    def test_unknown_option(self):
        self.assertEqual(run_main(["--nope", "file:x"])[0], 2)


if __name__ == "__main__":
    unittest.main()
