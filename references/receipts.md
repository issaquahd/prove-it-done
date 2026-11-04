# Receipts

A receipt is one line that backs one completion claim and can be re-run by anyone, at any time, against the real system. This page is the full reference for the format the verifier reads.

## Grammar

```
KIND:TARGET [ | key=value ]...
```

- `KIND` is one of `cmd`, `sh`, `file`, `dir`, `http`, `commit`, `said`.
- `TARGET` is everything after the first colon up to the first option.
- Options are separated by a space, a pipe and a space, and the separator only counts when the next word is a known option key followed by `=`. So a shell pipeline such as `sh:ps aux | grep -q nginx` keeps its pipe, and `sh:ps aux | grep -q nginx | timeout=5` has one option.
- Option values run to the next separator. Do not wrap them in quotes; quotes become part of the value.

## Kinds

| Kind | Target | PASS when | Options |
| --- | --- | --- | --- |
| `cmd:` | a command line, split the way a POSIX shell splits words, run **without** a shell | exit status equals `rc` (default 0), and the output contains `contains` if given | `rc=N`, `contains=TEXT`, `timeout=S` |
| `sh:` | a shell string, run through the system shell (`/bin/sh` or `cmd.exe`) | as `cmd:`; refused unless the verifier was started with `--allow-shell` | `rc=N`, `contains=TEXT`, `timeout=S` |
| `file:` | a path (`~` expands) | it is a regular file, and its SHA-256 equals `sha256` if given | `sha256=HEX` (only on `file:`; on any other kind it is a parse error, because a listing, a size or an exit code is not a checksum) |
| `dir:` | a path | it is a directory | |
| `http:` | an `http://` or `https://` URL | a GET returns a 2xx status (or one listed in `status`), after redirects, and the first 2 MB of the body contain `contains` if given | `status=200[,204]`, `contains=TEXT`, `timeout=S` |
| `commit:` | a commit hash, 7 to 64 hex characters | the commit exists in `repo` (default `.`); it changes `path` if given (compared with its first parent, so a merge commit counts the files it brought into the branch); it is an ancestor of `branch` if given | `repo=PATH`, `path=FILE`, `branch=REF` |
| `said:` | free text | never: printed as `CLAIM` and not counted | |

Options that apply to every kind:

- `via=NAME` names the instrument. Use it when the default would hide that two receipts observe through the same thing (two different binaries that both read the same cache), or would split one instrument into two.
- `proves=config` marks a receipt that reads configuration or desired state rather than behaviour. A done step needs at least one passing receipt that is not `proves=config`.
- `target=NAME` names the object the receipt is about. NAME must be what the check reads: a whole word of the command (also the value in `--flag=NAME` or `key=NAME`), the path or a path ending in `/NAME`, the URL host or path, or the commit's `path=`. Otherwise the receipt FAILs: `cmd:svcctl status web-canary | target=web` checks the canary, not `web`.

## Claimed target

A done step can name the object it claims with a line under the step. On the command line, use `--target NAME`.

```markdown
- [x] 1. web runs 2.4.1 in production
  - target: web
  - receipt: `cmd:svcctl status web | contains=running version=2.4.1`
- [x] 2. orders backup is verified
  - target: backups/orders.dump | needs=sha256
  - receipt: `file:backups/orders.dump | sha256=...`
```

With a target, only behaviour receipts about NAME count. A receipt is about NAME when its `target=` is NAME, or when it has no `target=` and its check reads NAME (as for `target=` above). The match is on whole words, so `web-canary` is not `web`. A receipt about another object is printed and not counted, and `--min-instruments` counts only receipts about NAME. A step whose passing behaviour receipts are all about other objects is UNPROVEN. `needs=sha256` also needs a passing `file:` receipt on NAME with `sha256=`: a listing (name and size) or an existence check does not show that the content is right. Steps without a `- target:` line are judged as before.

## Baselines (fail before, pass after)

A receipt that passes on the state before the change would pass with no change at all, so it is not evidence of the change. These options make the verifier check that too:

| Option | Kinds | What the verifier does |
| --- | --- | --- |
| `baseline=REF` | `cmd:`, `sh:`, `file:`, `dir:` | Creates a temporary, detached git worktree at `REF` (any commit-ish: `HEAD` for uncommitted work, `HEAD~1` after committing) of the repository that holds the current directory, with hooks disabled. It runs the same receipt there from the same relative directory, with `file:` and `dir:` paths mapped into the worktree, then removes the worktree. |
| `keep=PATH[,PATH]` | with `baseline=` | Copies these files or directories (relative to the current directory, inside the repository) from the current tree into the worktree before the run, so a test written in the change runs against the old code. |
| `before=STATE` | `file:`, `dir:` | Uses a recorded pre-change state instead of git: `absent`, `present`, or the file's old SHA-256. |

Verdicts, printed after the receipt's own result:

- **PROVEN**: fails before the change, passes after. The receipt is evidence of the change.
- **VACUOUS**: passes before and after. The line is tagged `VACUOUS` and the receipt is not counted as evidence or toward `--min-instruments`.
- **BROKEN**: fails after the change. The receipt is a FAIL, as without a baseline.
- **N/A**: no baseline was possible. `http:`, `commit:` and `said:` have no pre-change state to re-check. A baseline run that errors (unknown ref, checkout failure, timeout, missing program) is also N/A: a check that errors proves nothing, so an errored baseline is never read as "fails before". The receipt counts as it would without a baseline and never as PROVEN.

Two cases are reported N/A because they would otherwise look PROVEN or VACUOUS for the wrong reason:

- the command names a file that exists now but not at `REF` (a test written in the change), and `keep=` does not carry it: the baseline would only show that the test did not exist yet;
- the command names a repository file by absolute path: the baseline run would read the current tree.

`--require-baseline` makes a done step PROVEN only when at least one passing behaviour receipt is PROVEN against its baseline and no receipt in the step is VACUOUS. When any receipt has a baseline, the run ends with `baseline: N proven, N vacuous, N broken, N n/a`.

Limits: the worktree has tracked files at `REF` plus `keep=` paths, and no untracked build outputs or installed state. A baseline cannot rewind a database, a service or anything outside the repository; for those, record `before=` or accept N/A. A test found by discovery (`python -m unittest discover`) rather than named on the command line is not detected as new; name it, or `keep=` its directory.

## Instruments

The verifier derives an instrument for each receipt unless `via=` is given:

| Kind | Default instrument |
| --- | --- |
| `cmd:`, `sh:` | the program name (`kubectl`, `curl`, `psql`), ignoring leading `VAR=value` words |
| `http:` | `http:` plus the host name |
| `file:`, `dir:` | `filesystem` |
| `commit:` | `git` |
| `said:` | `self-report` (never counted) |

`--min-instruments N` makes a step PROVEN only when its passing behaviour receipts come from N distinct instruments. Config receipts never count toward N: reading a manifest through a second tool does not independently confirm what the system does. Two `curl` calls to the same host are one instrument. A `curl` and a database query are two.

The default is a guess based on names. If an `http:` receipt and a `cmd:curl` receipt hit the same endpoint, they observe the same thing; tag both `via=` with the same name so they count once.

## Choosing a receipt for a claim

| Claim | Behaviour receipt (counts) | Config receipt (`proves=config`, does not count alone) |
| --- | --- | --- |
| Service runs version X | `http:` on a version or health endpoint with `contains=X` | the deployment manifest or image tag |
| Setting changed to Y | the running service's effective config, or an action whose result depends on Y | the config file's hash or content |
| Page is published | `http:` on the public URL with `status=200` and `contains=` a phrase from the new text | the commit that adds the page |
| Fix works | the failing test or reproduction, now passing | the commit that changes the code |
| File written | `file:` with `sha256=` (the file *is* the deliverable) | |
| Job scheduled | the scheduler's own listing of the job, or its next-run record | the job definition file |
| Data migrated | a query that counts or samples the migrated rows | the migration file or its applied marker |
| Message sent | the recipient side, or the provider's delivery record | the outbox entry |

A `file:` or `commit:` receipt is behaviour only when the file or commit is itself the deliverable. When the claim is about what a system *does*, they are config.

## Output

One line per receipt:

```
PASS  [1] http:https://staging.example.com/version | status=200 | contains=2.1.0 -- HTTP 200, body contains the expected text (via http:staging.example.com)
FAIL  [2] cmd:logctl show-policy app | contains=keep=7 -- exit 0 but output does not contain the expected text (via logctl)
CLAIM [3] said:worker-2 reported RESULT=ok -- a self-report is a claim, not evidence; it does not count (via self-report)
```

In ledger mode, each done step gets a verdict line (`-> PROVEN: ...` or `-> UNPROVEN: reason`), and a summary line ends the run. Open steps (`- [ ]`) are checked and printed but not judged.

- Command output is never printed. To see why a `cmd:` failed, run it yourself.
- Every printed line goes through a redactor that masks credentials in URLs (`user:pass@`, `?token=`), secret-named flags (`--password=`, `--api-key`), `Authorization` headers, `NAME_TOKEN=` style assignments, and common token shapes. A redactor is a safety net, not a guarantee; keep secrets out of receipts (see `SECURITY.md`).
- Errors (timeouts, refused connections, DNS failures, missing programs, unknown branches) are FAIL with the words "a check that errors proves nothing".

Exit status: 0 when every done step is PROVEN (on the command line, when every receipt passes); 1 otherwise; 2 for a usage or parse error.

## Ledger format

```markdown
# Ledger: <task>

- [x] 1. <claim as an observable fact>
  - receipt: `<spec>`
  - receipt: `<spec>`
- [ ] 2. <next claim>
```

- A step line is `- [ ] N. text` or `- [x] N. text`, at any indent.
- A receipt line is an indented `- receipt: ` followed by the spec in single backticks, alone on the line. Anything else in the file is ignored, so notes, headings and links are fine.
- `--reopen` rewrites each done step that is not PROVEN into a struck-through line with the date and the reason, followed by a fresh open line. The receipts stay under the open line, ready for the next run. Nothing is removed. Running `--reopen` again changes nothing until a step is marked done again.

## Platform notes

- `cmd:` uses POSIX word splitting on every platform. On Windows, write paths with forward slashes or wrap them in single quotes, because a backslash is an escape character in POSIX splitting.
- `sh:` uses `/bin/sh` on POSIX and `cmd.exe` on Windows, so `sh:` receipts are rarely portable. Prefer `cmd:`.
- On POSIX, a `sh:` receipt that times out may leave child processes running, because only the shell is killed.
- `http:` uses the system's certificate store through Python's default TLS settings, and sends no cookies or credentials.
