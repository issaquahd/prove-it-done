#!/usr/bin/env python3
"""verify_receipts.py - re-run completion receipts against the real system.

A receipt is a one-line, re-runnable check that backs one completion claim.
This script runs each receipt now and prints PASS or FAIL for it. It never
trusts a transcript, a log line, or anyone's word: only what the check sees.

Usage:
  verify_receipts.py [options] SPEC [SPEC ...]     check receipts given on the command line
  verify_receipts.py [options] --ledger FILE       check every receipt in a receipt ledger
  verify_receipts.py --ledger FILE --reopen        ...and reopen done steps that are not proven

Options:
  --timeout N          default per-receipt timeout in seconds (default 60)
  --allow-shell        permit sh: receipts (they run through the system shell)
  --min-instruments N  a claim needs passing behaviour receipts from N distinct instruments (default 1)
  --require-baseline   a claim needs a behaviour receipt that fails before the change and passes
                       after it, and any VACUOUS receipt makes the claim unproven
  --target CLAIM       the object the claim is about (see "Claimed target" below); command line only
  --list               parse and print the receipts without running them

Receipt spec:  KIND:TARGET [ | key=value ]...

  cmd:ARGV        run ARGV without a shell (split like a POSIX shell would); PASS on exit 0
                  options: rc=N  contains=TEXT  timeout=S
  sh:STRING       run STRING through the system shell; needs --allow-shell (see SECURITY.md)
                  options: rc=N  contains=TEXT  timeout=S
  file:PATH       PATH is a regular file; options: sha256=HEX (sha256= works only on file:; a
                  listing, a size or an exit code is not a checksum)
  dir:PATH        PATH is a directory
  http:URL        GET URL (http or https); PASS on any 2xx unless status= is given
                  options: status=200[,204]  contains=TEXT  timeout=S
  commit:HASH     HASH is a commit; options: repo=PATH (default .)  path=FILE (the commit
                  touches FILE)  branch=REF (REF contains the commit)
  said:TEXT       record a self-report ("worker says RESULT=ok"). Printed as CLAIM and never
                  counted: a claim is not evidence. A step backed only by said: is unproven.

Options for every kind:
  via=NAME        name the instrument (default: derived from the receipt)
  proves=config   mark a receipt that only checks configuration, not behaviour
  target=NAME     the object this receipt is about. NAME must be what the check reads (a word
                  of the command, the path, or the URL host or path), or the receipt FAILs:
                  "cmd:svc status web-canary | target=web" checks web-canary, not web.

Claimed target: a done step may name the object it claims with a line under the step,
  "- target: NAME" (or --target NAME on the command line). Then only behaviour receipts
  about NAME count: one with target=NAME, or with no target= and NAME as a word of its check.
  A receipt about another object is printed and not counted. "- target: NAME | needs=sha256"
  also needs a passing file: receipt on NAME with sha256=: a listing (name and size) or an
  existence check does not show the content is right.

Baseline (fail before, pass after): a receipt that already passes on the pre-change state
is not evidence of the change.
  baseline=REF    cmd:, sh:, file:, dir: run the same check again in a temporary git worktree
                  at REF (for example HEAD~1); the repository is the one holding the current
                  directory. keep=PATH[,PATH] copies files from the current tree into that
                  worktree first, so a new test can run against the old code.
  before=STATE    file:, dir: the recorded pre-change state: absent, present, or the file's
                  old SHA-256
  Baseline verdicts: PROVEN (fails before, passes after), VACUOUS (passes before and after:
  not evidence), BROKEN (fails after), N/A (no baseline possible: http:, commit:, said:, or
  the baseline check errored). N/A is never counted as a baseline.

Exit status: 0 when every done step is proven (on the command line, every receipt
passes), 1 otherwise, 2 on a usage or parse error. Receipts under open steps are run
and printed but do not change the exit status. Command output is never printed, and every printed line
is passed through a redactor for credentials in URLs, flags, headers and env assignments.
"""
import datetime
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

KINDS = ("cmd", "sh", "file", "dir", "http", "commit", "said")
OPTION_KEYS = ("rc", "contains", "timeout", "sha256", "status", "repo", "path", "branch", "via", "proves",
               "baseline", "before", "keep", "target")
NEEDS = ("sha256",)
OPTION_SPLIT = re.compile(r"\s+\|\s+(?=(?:%s)=)" % "|".join(OPTION_KEYS))
HEX_HASH = re.compile(r"^[0-9a-fA-F]{7,64}$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
HTTP_BODY_LIMIT = 2 * 1024 * 1024


class SpecError(ValueError):
    pass


# ------------------------------------------------------------------ redaction

_SECRET_WORD = r"(?:token|secret|password|passwd|pwd|api[-_]?key|access[-_]?key|private[-_]?key|auth|credential|session|sig|signature)"
_REDACTIONS = [
    # scheme://user:pass@host  and  scheme://token@host
    (re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@]+@"), r"\1***@"),
    # ?token=...&api_key=...
    (re.compile(r"([?&;][^=&\s#]*" + _SECRET_WORD + r"[^=&\s#]*=)[^&\s#]+", re.I), r"\1***"),
    # Authorization: Bearer xyz / Basic xyz
    (re.compile(r"(authorization\s*[:=]\s*)(?:(?:bearer|basic|token)\s+)?[^\s'\"]+", re.I), r"\1***"),
    (re.compile(r"(\bbearer\s+)[^\s'\"]+", re.I), r"\1***"),
    # --password=x, --api-key x, -p? (only named secret flags)
    (re.compile(r"(--?[\w-]*" + _SECRET_WORD + r"[\w-]*(?:=|\s+))(?!-)[^\s'\"]+", re.I), r"\1***"),
    # API_TOKEN=x  DB_PASSWORD=x
    (re.compile(r"\b([A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH|CREDENTIALS?)[A-Za-z0-9_]*=)[^\s'\"]+", re.I), r"\1***"),
    # well-known token shapes
    (re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr|github_pat|glpat|sk|sk-ant|xox[abprs])[-_][A-Za-z0-9_\-]{10,}"), "***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "***"),
]


def redact(text):
    """Remove credentials from text before it is printed."""
    s = str(text)
    for pattern, repl in _REDACTIONS:
        s = pattern.sub(repl, s)
    return s


# ------------------------------------------------------------------ parsing

class Receipt(object):
    def __init__(self, spec, kind, target, options):
        self.spec = spec
        self.kind = kind
        self.target = target
        self.options = options

    @property
    def proves(self):
        return self.options.get("proves", "behaviour").lower()

    @property
    def wants_baseline(self):
        return "baseline" in self.options or "before" in self.options

    def instrument(self):
        if "via" in self.options:
            return self.options["via"]
        if self.kind in ("cmd", "sh"):
            try:
                words = shlex.split(self.target)
            except ValueError:
                words = self.target.split()
            words = [w for w in words if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w)]
            head = words[0] if words else "?"
            name = re.split(r"[\\/]", head)[-1]
            return re.sub(r"\.exe$", "", name, flags=re.I)
        if self.kind == "http":
            host = urllib.parse.urlsplit(self.target).hostname or "?"
            return "http:" + host
        if self.kind in ("file", "dir"):
            return "filesystem"
        if self.kind == "commit":
            return "git"
        return "self-report"


def parse_spec(spec):
    spec = spec.strip()
    kind, sep, rest = spec.partition(":")
    kind = kind.strip().lower()
    if not sep or kind not in KINDS:
        raise SpecError("unknown receipt kind in %r (expected one of %s)" % (redact(spec[:40]), ", ".join(KINDS)))
    parts = OPTION_SPLIT.split(rest)
    target = parts[0].strip()
    if not target:
        raise SpecError("receipt %r has no target" % redact(spec))
    options = {}
    for p in parts[1:]:
        key, _, value = p.partition("=")
        options[key.strip()] = value.strip()
    if "proves" in options and options["proves"].lower() not in ("config", "behaviour", "behavior"):
        raise SpecError("proves= must be config or behaviour, got %r" % options["proves"])
    if options.get("proves", "").lower() == "behavior":
        options["proves"] = "behaviour"
    if "baseline" in options and "before" in options:
        raise SpecError("use baseline= or before=, not both")
    if "keep" in options and "baseline" not in options:
        raise SpecError("keep= needs baseline=")
    if "sha256" in options and kind != "file":
        raise SpecError("sha256= works only on file: receipts; a listing, a size or an exit code is not a checksum")
    if "target" in options and not options["target"]:
        raise SpecError("target= needs a name")
    return Receipt(spec, kind, target, options)


# ------------------------------------------------------------------ targets

def _norm_name(name):
    n = name.strip().strip("'\"").replace("\\", "/")
    while n.startswith("./"):
        n = n[2:]
    return n.rstrip("/") or n


def _same_object(word, name):
    """True when WORD (from a check) names NAME: equal, or a path ending in /NAME."""
    w, n = _norm_name(word), _norm_name(name)
    return w == n or w.endswith("/" + n)


def check_words(receipt):
    """The names a receipt's check reads: words of the command, the path, the URL host and
    path, the commit and its path=."""
    if receipt.kind in ("cmd", "sh"):
        try:
            words = shlex.split(receipt.target)
        except ValueError:
            words = receipt.target.split()
        out = []
        for w in words:
            out.append(w)
            out.extend(x for x in re.split(r"[=,]", w) if x and x != w)
        return out
    if receipt.kind == "http":
        u = urllib.parse.urlsplit(receipt.target)
        segs = [x for x in u.path.split("/") if x]
        return [x for x in [u.hostname or "", u.path] + segs if x]
    if receipt.kind == "commit":
        return [receipt.target] + [receipt.options[k] for k in ("path", "repo") if k in receipt.options]
    if receipt.kind in ("file", "dir"):
        return [receipt.target]
    return []


def reads(receipt, name):
    """True when the receipt's check reads NAME."""
    return any(_same_object(w, name) for w in check_words(receipt))


def about(receipt, name):
    """True when the receipt is about NAME: its target= is NAME, or it has no target= and its
    check reads NAME."""
    if "target" in receipt.options:
        return _norm_name(receipt.options["target"]) == _norm_name(name)
    return reads(receipt, name)


class Claim(object):
    """The object a step claims, from "- target: NAME [| needs=sha256]"."""

    def __init__(self, name, needs=None):
        self.name = name
        self.needs = needs


def parse_claim(text):
    parts = re.split(r"\s+\|\s+", text.strip())
    name = parts[0].strip().strip("`")
    if not name:
        raise SpecError("target: needs a name")
    needs = None
    for p in parts[1:]:
        key, _, value = p.partition("=")
        if key.strip() != "needs" or value.strip() not in NEEDS:
            raise SpecError("target: options are needs=%s, got %r" % ("|".join(NEEDS), redact(p)))
        needs = value.strip()
    return Claim(name, needs)


# ------------------------------------------------------------------ checks

def _timeout(receipt, default):
    try:
        return float(receipt.options.get("timeout", default))
    except ValueError:
        raise SpecError("timeout= must be a number of seconds")


def _run_process(receipt, default_timeout, allow_shell, cwd=None):
    if receipt.kind == "sh" and not allow_shell:
        return False, "sh: receipts run through the system shell; re-run with --allow-shell if you trust this ledger"
    timeout = _timeout(receipt, default_timeout)
    try:
        expected_rc = int(receipt.options.get("rc", "0"))
    except ValueError:
        raise SpecError("rc= must be an integer")
    if receipt.kind == "cmd":
        try:
            argv = shlex.split(receipt.target)
        except ValueError as e:
            return False, "cannot split command: %s" % e
        if not argv:
            return False, "empty command"
        popen_args = dict(args=argv, shell=False)
    else:
        popen_args = dict(args=receipt.target, shell=True)
    try:
        proc = subprocess.run(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, cwd=cwd, **popen_args)
    except subprocess.TimeoutExpired:
        return False, "error: timed out after %gs; a check that does not finish proves nothing" % timeout
    except OSError as e:
        return False, "error: could not start command (%s); a check that errors proves nothing" % e.__class__.__name__
    if proc.returncode != expected_rc:
        return False, "exit %d, expected %d" % (proc.returncode, expected_rc)
    if "contains" in receipt.options:
        out = (proc.stdout or b"") + b"\n" + (proc.stderr or b"")
        if receipt.options["contains"].encode("utf-8") not in out:
            return False, "exit %d but output does not contain the expected text" % proc.returncode
        return True, "exit %d, output contains the expected text" % proc.returncode
    return True, "exit %d" % proc.returncode


def _check_file(receipt):
    path = os.path.expanduser(receipt.target)
    if receipt.kind == "dir":
        return (True, "directory exists") if os.path.isdir(path) else (False, "no such directory")
    if not os.path.isfile(path):
        return False, "no such file"
    want = receipt.options.get("sha256")
    if want is None:
        return True, "file exists (%d bytes)" % os.path.getsize(path)
    if not SHA256.match(want):
        raise SpecError("sha256= must be 64 hex characters")
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    got = h.hexdigest()
    if got == want.lower():
        return True, "sha256 matches"
    return False, "sha256 is %s..., expected %s..." % (got[:12], want.lower()[:12])


class _HttpOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to http and https URLs (urllib alone would also follow ftp)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() not in ("http", "https"):
            raise urllib.error.URLError("redirect to a non-http(s) URL refused")
        return urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)


def _check_http(receipt, default_timeout):
    url = receipt.target
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        return False, "only http and https URLs are checked, got %r" % scheme
    timeout = _timeout(receipt, default_timeout)
    wanted = None
    if "status" in receipt.options:
        try:
            wanted = [int(x) for x in receipt.options["status"].split(",")]
        except ValueError:
            raise SpecError("status= must be one or more integers separated by commas")
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "prove-it-done-verifier/0.1"})
    opener = urllib.request.build_opener(_HttpOnlyRedirect)
    try:
        resp = opener.open(req, timeout=timeout)
        status, body = resp.status, resp.read(HTTP_BODY_LIMIT)
        resp.close()
    except urllib.error.HTTPError as e:
        status, body = e.code, b""
        try:
            body = e.read(HTTP_BODY_LIMIT)
        except Exception:
            pass
    except Exception as e:  # URLError, timeout, TLS, DNS: the check itself failed
        reason = getattr(e, "reason", e)
        return False, "error: request failed (%s); a check that errors proves nothing" % redact(reason)
    ok = (status in wanted) if wanted else (200 <= status < 300)
    expect = ",".join(str(w) for w in wanted) if wanted else "2xx"
    if not ok:
        return False, "HTTP %d, expected %s" % (status, expect)
    if "contains" in receipt.options:
        if receipt.options["contains"].encode("utf-8") not in body:
            return False, "HTTP %d but body does not contain the expected text" % status
        return True, "HTTP %d, body contains the expected text" % status
    return True, "HTTP %d" % status


def _git(repo, *args):
    return subprocess.run(["git", "-C", repo] + list(args), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)


def _check_commit(receipt):
    h = receipt.target
    if not HEX_HASH.match(h):
        raise SpecError("commit hash must be 7 to 64 hex characters")
    repo = os.path.expanduser(receipt.options.get("repo", "."))
    if not os.path.isdir(repo):
        return False, "repo directory not found"
    try:
        if _git(repo, "cat-file", "-e", h + "^{commit}").returncode != 0:
            return False, "commit %s not found in repo" % h
        notes = ["commit %s exists" % h]
        path = receipt.options.get("path")
        if path:
            # Files changed relative to the first parent, so a merge commit lists what it
            # brought into the branch. A root commit lists every file it adds.
            parents = _git(repo, "rev-list", "--parents", "-n", "1", h).stdout.decode().split()[1:]
            if parents:
                out = _git(repo, "diff", "--name-only", parents[0], h)
            else:
                out = _git(repo, "show", "--name-only", "--format=", h)
            out = out.stdout.decode("utf-8", "replace")
            want = path.replace("\\", "/")
            while want.startswith("./"):
                want = want[2:]
            if want not in [f.strip() for f in out.splitlines() if f.strip()]:
                return False, "commit %s does not touch %s" % (h, path)
            notes.append("touches %s" % path)
        branch = receipt.options.get("branch")
        if branch:
            if branch.startswith("-") or re.search(r"\s", branch):
                raise SpecError("branch= must be a ref name")
            rc = _git(repo, "merge-base", "--is-ancestor", h, branch).returncode
            if rc == 1:
                return False, "commit %s is not on %s" % (h, branch)
            if rc != 0:
                return False, "error: could not resolve %s; a check that errors proves nothing" % branch
            notes.append("is on %s" % branch)
        return True, ", ".join(notes)
    except OSError:
        return False, "error: git is not available; a check that errors proves nothing"
    except subprocess.TimeoutExpired:
        return False, "error: git timed out; a check that errors proves nothing"


def check(receipt, default_timeout=60.0, allow_shell=False, cwd=None):
    """Run one receipt now. Returns (ok, message); ok is None for said: lines, which are
    recorded claims, not checks. Never raises for a failing system."""
    if "target" in receipt.options and receipt.kind != "said" and not reads(receipt, receipt.options["target"]):
        return False, "target=%s is not what this check reads; a check on another object proves nothing about it" % (
            receipt.options["target"])
    try:
        if receipt.kind in ("cmd", "sh"):
            return _run_process(receipt, default_timeout, allow_shell, cwd)
        if receipt.kind in ("file", "dir"):
            return _check_file(receipt)
        if receipt.kind == "http":
            return _check_http(receipt, default_timeout)
        if receipt.kind == "commit":
            return _check_commit(receipt)
        if receipt.kind == "said":
            return None, "a self-report is a claim, not evidence; it does not count"
    except SpecError as e:
        return False, "bad receipt: %s" % e
    except Exception as e:  # an unexpected error in the check is not a pass
        return False, "error: %s; a check that errors proves nothing" % e.__class__.__name__
    return False, "unknown receipt kind"


# ------------------------------------------------------------------ baseline

PROVEN, VACUOUS, BROKEN, NA = "PROVEN", "VACUOUS", "BROKEN", "N/A"


def _is_error(msg):
    return msg.startswith("error:") or msg.startswith("bad receipt")


def _before_state(receipt):
    """Judge a file:/dir: receipt against its recorded before= state. Returns (ok, msg)."""
    state = receipt.options["before"].strip().lower()
    if state == "absent":
        return False, "absent before the change"
    if receipt.kind == "dir":
        if state == "present":
            return True, "present before the change"
        raise SpecError("before= for dir: must be absent or present")
    if state == "present":
        if "sha256" in receipt.options:
            raise SpecError("before=present cannot be compared with sha256=; record the old SHA-256")
        return True, "present before the change"
    if not SHA256.match(state):
        raise SpecError("before= for file: must be absent, present or 64 hex characters")
    if "sha256" not in receipt.options:
        return True, "present before the change"
    if state == receipt.options["sha256"].lower():
        return True, "same sha256 before the change"
    return False, "sha256 was %s... before the change" % state[:12]


def _inside(path, top):
    rel = os.path.relpath(path, top)
    return rel != os.pardir and not rel.startswith(os.pardir + os.sep) and not os.path.isabs(rel)


def _worktree_baseline(receipt, default_timeout, allow_shell):
    """Re-run a cmd:/sh:/file:/dir: receipt in a temporary worktree at baseline=REF.
    Returns (ok, msg); ok is None when the baseline could not be checked."""
    ref = receipt.options["baseline"]
    if not ref or ref.startswith("-") or re.search(r"\s", ref):
        raise SpecError("baseline= must be a git ref")
    cwd = os.getcwd()
    top = _git(cwd, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return None, "the current directory is not in a git repository"
    top = os.path.realpath(top.stdout.decode().strip())
    sha = _git(top, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
    if sha.returncode != 0:
        return None, "error: could not resolve %s; a check that errors proves nothing" % ref
    sha = sha.stdout.decode().strip()
    rel_cwd = os.path.relpath(os.path.realpath(cwd), top)

    keep = [k.strip() for k in receipt.options.get("keep", "").split(",") if k.strip()]
    for k in keep:
        if os.path.isabs(k) or not _inside(os.path.realpath(k), top):
            raise SpecError("keep= paths must be relative and inside the repository")
        if not os.path.exists(k):
            return None, "error: keep=%s does not exist; a check that errors proves nothing" % k

    # Paths the check reads must be resolvable in the worktree, not in the current tree.
    if receipt.kind in ("file", "dir"):
        path = os.path.realpath(os.path.expanduser(receipt.target))
        if not _inside(path, top):
            return None, "%s is outside the repository" % receipt.target
        words = []
    else:
        try:
            words = shlex.split(receipt.target)
        except ValueError:
            words = receipt.target.split()
        words = [w for w in words if not os.path.isabs(w) or _inside(os.path.realpath(w), top)]

    parent = tempfile.mkdtemp(prefix="prove-it-done-baseline-")
    wt = os.path.join(parent, "wt")
    hooks = os.path.join(parent, "no-hooks")
    os.mkdir(hooks)
    try:
        add = _git(top, "-c", "core.hooksPath=" + hooks, "worktree", "add", "--detach", "-q", wt, sha)
        if add.returncode != 0:
            return None, "error: could not check out %s; a check that errors proves nothing" % ref
        wt_cwd = os.path.normpath(os.path.join(wt, rel_cwd))
        for k in keep:
            src, dst = os.path.join(cwd, k), os.path.join(wt_cwd, k)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
                shutil.copy2(src, dst)
        if receipt.kind in ("file", "dir"):
            mapped = os.path.join(wt, os.path.relpath(path, top))
            target = Receipt(receipt.spec, receipt.kind, mapped, receipt.options)
            return check(target, default_timeout, allow_shell)
        if not os.path.isdir(wt_cwd):
            return None, "directory %s does not exist at %s" % (rel_cwd, ref)
        for w in words:
            if os.path.isabs(w):
                # a repository file named by absolute path would be read from the current tree
                if os.path.isfile(w) and _git(top, "check-ignore", "-q", w).returncode != 0:
                    return None, ("the check names %s by absolute path, so a baseline run would read "
                                  "the current tree; use a path relative to the current directory" % w)
            elif os.path.isfile(w) and not os.path.exists(os.path.join(wt_cwd, w)):
                return None, ("the check uses %s, which does not exist at %s; add keep=%s to run the "
                              "new check against the old code" % (w, ref, w))
        return check(receipt, default_timeout, allow_shell, cwd=wt_cwd)
    finally:
        _git(top, "worktree", "remove", "--force", wt)
        shutil.rmtree(parent, ignore_errors=True)
        _git(top, "worktree", "prune")


def check_baseline(receipt, ok, default_timeout=60.0, allow_shell=False):
    """Judge a receipt that asked for a baseline (baseline= or before=) against the
    pre-change state. ok is the receipt's result now. Returns (verdict, message)."""
    if ok is False:
        return BROKEN, "fails after the change"
    if receipt.kind in ("http", "commit", "said"):
        return NA, "%s: receipts have no pre-change state to re-check" % receipt.kind
    try:
        if "before" in receipt.options:
            if receipt.kind not in ("file", "dir"):
                raise SpecError("before= applies to file: and dir: only; use baseline=REF")
            before_ok, before_msg = _before_state(receipt)
            where = "recorded"
        else:
            before_ok, before_msg = _worktree_baseline(receipt, default_timeout, allow_shell)
            where = receipt.options["baseline"]
    except SpecError as e:
        return NA, "bad receipt: %s" % e
    except (OSError, subprocess.TimeoutExpired) as e:
        return NA, "error: %s; a check that errors proves nothing" % e.__class__.__name__
    if before_ok is None or (before_ok is False and _is_error(before_msg)):
        return NA, "baseline %s not checked: %s" % (where, before_msg)
    if before_ok:
        return VACUOUS, "baseline %s: %s; it passes before the change too, so it is not evidence" % (
            where, before_msg)
    return PROVEN, "baseline %s: %s; fails before the change, passes after" % (where, before_msg)


# ------------------------------------------------------------------ ledger

ITEM = re.compile(r"^(\s*)- \[([ xX])\] (\d+)\. (.*)$")
RECEIPT_LINE = re.compile(r"^\s+- receipt: `(.+)`\s*$")
TARGET_LINE = re.compile(r"^\s+- target: (.+?)\s*$")


class Step(object):
    def __init__(self, line_no, number, text, done):
        self.line_no = line_no
        self.number = number
        self.text = text
        self.done = done
        self.receipts = []  # (line_no, Receipt)
        self.claim = None  # Claim, from a "- target:" line


def parse_ledger(text):
    steps, current = [], None
    for i, line in enumerate(text.splitlines()):
        m = ITEM.match(line)
        if m:
            current = Step(i, m.group(3), m.group(4), m.group(2) in "xX")
            steps.append(current)
            continue
        r = RECEIPT_LINE.match(line)
        if r and current is not None:
            current.receipts.append((i, parse_spec(r.group(1))))
            continue
        t = TARGET_LINE.match(line)
        if t and current is not None:
            current.claim = parse_claim(t.group(1))
    return steps


def _numbers(label, idx):
    return "%s %s" % (label if len(idx) == 1 else label + "s", ", ".join(str(i) for i in idx))


def judge(results, min_instruments, require_baseline=False, claim=None):
    """results: list of (Receipt, ok, msg) or (Receipt, ok, msg, baseline_verdict), where
    baseline_verdict is None for a receipt that asked for no baseline. claim: the Claim the
    step makes, or None. Returns (proven, reason)."""
    if not results:
        return False, "no receipts"
    results = [tuple(x) + (None,) * (4 - len(x)) for x in results]
    failed = [i for i, x in enumerate(results, 1) if x[1] is False]
    if failed:
        return False, "%s failed" % _numbers("receipt", failed)
    vacuous = [i for i, x in enumerate(results, 1) if x[3] == VACUOUS]
    results = [x for x in results if x[0].kind != "said"]
    if not results:
        return False, "only self-reports; a claim is not evidence"
    if require_baseline and vacuous:
        return False, "%s VACUOUS: passes before the change too, so it is not evidence" % _numbers(
            "receipt", vacuous)
    behaviour = [(r, v) for r, ok, _, v in results if ok and r.proves != "config" and v != VACUOUS]
    off = []
    if claim is not None and behaviour:
        off = [r for r, _ in behaviour if not about(r, claim.name)]
        behaviour = [(r, v) for r, v in behaviour if about(r, claim.name)]
        if not behaviour:
            return False, "no passing behaviour receipt is about the claimed target %s; a check on another object proves nothing about it" % claim.name
        if claim.needs == "sha256" and not any(r.kind == "file" and "sha256" in r.options for r, _ in behaviour):
            return False, ("the claim needs the sha256 of %s; a listing (name and size) or an existence check "
                           "does not show the content is right" % claim.name)
    if not behaviour:
        if vacuous:
            return False, "only VACUOUS behaviour receipts passed; a receipt that passes before the change is not evidence"
        return False, "only config receipts passed; a config check is not a behaviour check"
    instruments = sorted(set(r.instrument() for r, _ in behaviour))
    if len(instruments) < min_instruments:
        return False, "%d behaviour receipt(s) through %d instrument(s) (%s); need %d distinct" % (
            len(behaviour), len(instruments), ", ".join(instruments), min_instruments)
    baselined = sum(1 for _, v in behaviour if v == PROVEN)
    if require_baseline and not baselined:
        return False, ("no behaviour receipt was shown to fail before the change; "
                       "--require-baseline needs one with baseline= or before=")
    note = "; %d failed before the change" % baselined if baselined else ""
    if vacuous:
        note += "; %s VACUOUS, not counted" % _numbers("receipt", vacuous)
    if off:
        note += "; %d receipt(s) about another object, not counted" % len(off)
    return True, "%d receipt(s); behaviour checked through %d instrument(s): %s%s" % (
        len(results), len(instruments), ", ".join(instruments), note)


def reopen(text, step_numbers_reasons, today=None):
    """Strike through done steps and add a fresh open line below. Never deletes a line."""
    today = today or datetime.date.today().isoformat()
    lines = text.splitlines(True)
    for line_no, (number, reason) in sorted(step_numbers_reasons.items(), reverse=True):
        line = lines[line_no]
        eol = "\n" if line.endswith("\n") else ""
        m = ITEM.match(line.rstrip("\n"))
        indent, body = m.group(1), m.group(4)
        lines[line_no] = "%s- ~~[x] %s. %s~~ reopened %s: %s%s" % (indent, number, body, today, reason, eol or "\n")
        lines.insert(line_no + 1, "%s- [ ] %s. %s%s" % (indent, number, body, eol))
    return "".join(lines)


# ------------------------------------------------------------------ main

def _print_receipt(idx, receipt, ok, msg, baseline=None):
    tag = "CLAIM" if ok is None else ("PASS" if ok else "FAIL")
    if baseline is not None:
        verdict, why = baseline
        tag = "VACUOUS" if verdict == VACUOUS else tag
        msg = "%s; %s: %s" % (msg, verdict, why)
    extra = " [config]" if receipt.proves == "config" else ""
    print(redact("%s  [%d] %s%s -- %s (via %s)" % (tag, idx, receipt.spec, extra, msg, receipt.instrument())))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    timeout, allow_shell, min_inst, list_only, do_reopen, ledger = 60.0, False, 1, False, False, None
    require_baseline = False
    claim_text = None
    specs = []
    it = iter(argv)
    try:
        for a in it:
            if a == "--timeout":
                timeout = float(next(it))
            elif a == "--allow-shell":
                allow_shell = True
            elif a == "--min-instruments":
                min_inst = int(next(it))
            elif a == "--require-baseline":
                require_baseline = True
            elif a == "--list":
                list_only = True
            elif a == "--reopen":
                do_reopen = True
            elif a == "--ledger":
                ledger = next(it)
            elif a == "--target":
                claim_text = next(it)
            elif a in ("-h", "--help"):
                print(__doc__)
                return 0
            elif a.startswith("--"):
                raise SpecError("unknown option %s" % a)
            else:
                specs.append(a)
    except (StopIteration, ValueError) as e:
        print("usage error: %s" % (e or "missing value"), file=sys.stderr)
        return 2
    except SpecError as e:
        print("usage error: %s" % e, file=sys.stderr)
        return 2
    if bool(ledger) == bool(specs) or (do_reopen and not ledger) or (claim_text is not None and ledger):
        print(__doc__, file=sys.stderr)
        return 2

    try:
        if ledger:
            with open(ledger, encoding="utf-8") as fh:
                text = fh.read()
            steps = parse_ledger(text)
        else:
            text = None
            step = Step(0, "-", "command-line receipts", True)
            step.receipts = [(0, parse_spec(s)) for s in specs]
            step.claim = parse_claim(claim_text) if claim_text is not None else None
            steps = [step]
    except (OSError, SpecError) as e:
        print("error: %s" % redact(e), file=sys.stderr)
        return 2

    if list_only:
        for s in steps:
            print(redact("step %s [%s] %s" % (s.number, "x" if s.done else " ", s.text)))
            for _, r in s.receipts:
                print(redact("  %s:%s  options=%s  via=%s  proves=%s" % (r.kind, r.target, r.options, r.instrument(), r.proves)))
            if s.claim is not None:
                print(redact("  target: %s%s" % (s.claim.name, " needs=%s" % s.claim.needs if s.claim.needs else "")))
        return 0

    n_pass = n_fail = 0
    verdicts = {PROVEN: 0, VACUOUS: 0, BROKEN: 0, NA: 0}
    unproven = {}
    idx = 0
    for s in steps:
        if ledger:
            print(redact("step %s%s %s" % (s.number, "" if s.done else " (open)", s.text)))
        results = []
        for _, r in s.receipts:
            idx += 1
            ok, msg = check(r, timeout, allow_shell)
            n_pass += ok is True
            n_fail += ok is False
            baseline = check_baseline(r, ok, timeout, allow_shell) if r.wants_baseline else None
            if baseline is not None:
                verdicts[baseline[0]] += 1
            results.append((r, ok, msg, baseline and baseline[0]))
            _print_receipt(idx, r, ok, msg, baseline)
        proven, reason = judge(results, min_inst, require_baseline, s.claim)
        if s.done:
            print(redact("  -> %s: %s" % ("PROVEN" if proven else "UNPROVEN", reason)))
            if not proven:
                unproven[s.line_no] = (s.number, reason)
        elif ledger:
            print("  -> open step, not judged")
    done_steps = sum(1 for s in steps if s.done)
    print("summary: %d pass, %d fail; %d of %d done step(s) proven" % (
        n_pass, n_fail, done_steps - len(unproven), done_steps))
    if any(verdicts.values()):
        print("baseline: %d proven, %d vacuous, %d broken, %d n/a" % (
            verdicts[PROVEN], verdicts[VACUOUS], verdicts[BROKEN], verdicts[NA]))
    if do_reopen and unproven:
        with open(ledger, "w", encoding="utf-8") as fh:
            fh.write(reopen(text, unproven))
        print("reopened step(s): %s" % ", ".join(n for n, _ in sorted(unproven.values())))
    return 0 if not unproven else 1


if __name__ == "__main__":
    sys.exit(main())
