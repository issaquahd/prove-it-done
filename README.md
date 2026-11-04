# prove-it-done

An agent skill for receipt-gated completion. Before an agent says "done", each claim gets a **receipt**: a one-line check that a bundled verifier re-runs against the real system and judges PASS or FAIL. A worker's "ok" is recorded but never counted. A config check alone does not prove behaviour. A check that errors proves nothing. A done step whose receipt fails is reopened with strike-through, not deleted.

```markdown
- [x] 1. Staging runs web 2.1.0
  - receipt: `said:deploy tool returned "ok: rollout started"`
  - receipt: `http:https://staging.example.com/version | status=200 | contains=2.1.0`
  - receipt: `cmd:kubectl -n staging rollout status deploy/web | contains=successfully rolled out`
```

```
$ python3 scripts/verify_receipts.py --ledger receipts.md --min-instruments 2
step 1 Staging runs web 2.1.0
CLAIM  [1] said:deploy tool returned "ok: rollout started" -- a self-report is a claim, not evidence; it does not count (via self-report)
PASS  [2] http:https://staging.example.com/version | status=200 | contains=2.1.0 -- HTTP 200, body contains the expected text (via http:staging.example.com)
PASS  [3] cmd:kubectl -n staging rollout status deploy/web | contains=successfully rolled out -- exit 0, output contains the expected text (via kubectl)
  -> PROVEN: 2 receipt(s); behaviour checked through 2 instrument(s): http:staging.example.com, kubectl
summary: 2 pass, 0 fail; 1 of 1 done step(s) proven
```

## Why

Agents say "done" when they have *tried*. The tool said ok, the worker printed `RESULT=ok`, the config file has the new value, a check ran before the final edit, the status call timed out but the deploy "succeeded". Each of these turns into a false completion report, and the person on the other end finds out later. The skill puts a small, mechanical step between the work and the word "done": write down how anyone could check the claim, run that check after the last change, and say only what passed.

The rules come from running agent fleets where every "done" step had to carry a receipt that a verifier re-ran:

1. A self-report is a claim, not evidence.
2. A confirmation names its instrument; two through the same instrument count as one.
3. A config check is not a behaviour check.
4. A check that errors proves nothing.
5. A check must come after the last change.
6. Reopen, never delete.

`references/rules.md` explains each rule and how it usually gets broken.

## How

**Install.** Copy this directory into your agent's skills folder (for Claude Code, `~/.claude/skills/prove-it-done/` or a project's `.claude/skills/`; for other runtimes, wherever they load `SKILL.md` skills). The agent loads `SKILL.md` when a request matches its description.

**Use.** The agent follows the seven steps in `SKILL.md`: list claims, pick instruments, write receipts in a Markdown ledger, record self-reports as `said:`, run the verifier after the last change, reopen on failure, and report only what is proven.

**Run the verifier yourself.** It needs Python 3.9 or later and nothing else.

```
python3 scripts/verify_receipts.py --ledger receipts.md            # check a ledger
python3 scripts/verify_receipts.py --ledger receipts.md --reopen   # ...and reopen unproven done steps
python3 scripts/verify_receipts.py 'file:dist/app.tar.gz | sha256=...' 'commit:4f2a9c1 | branch=main'
python3 scripts/verify_receipts.py --help
```

Receipt kinds: `cmd:` (no shell), `sh:` (shell, opt-in), `file:` (exists, SHA-256), `dir:`, `http:` (status, body text), `commit:` (exists, touches a path, on a branch), and `said:` (recorded self-report, never counted). The full reference is `references/receipts.md`.

**Fail before, pass after.** Add `| baseline=REF` to a `cmd:`, `sh:`, `file:` or `dir:` receipt and the verifier also runs it against the pre-change state. A receipt that passes there too is VACUOUS and does not count. See [Baselines](#baselines-fail-before-pass-after) below.

**Examples.** `examples/` has four worked ledgers with verifier output: a deploy, a config change, a published page, and a worker whose "ok" was false.

**Measure it.** `evals/evals.json` has eight test prompts. `evals/run.md` describes a with/without comparison scored by a deterministic unproven-completion detector, and shows the scorer working on four synthetic transcripts.

**Test.** `python3 -m unittest discover -s tests`. `.github/workflows/ci.yml` runs the same tests on Linux, macOS and Windows once the repository is on GitHub.

## Baselines: fail before, pass after

A receipt that already passes before the change is not evidence of the change. A test that always exits 0 passes after a real fix and after no fix at all. Grading pipelines for agent training check for this: they run the grader on an empty patch and require it to fail. In one production campaign, vacuous tests on two tasks made 22.9% of the positive labels wrong ([Sandman, arXiv 2610.39711](https://arxiv.org/abs/2610.39711)). `baseline=` applies the same check to a receipt.

- `baseline=REF` (on `cmd:`, `sh:`, `file:`, `dir:`) runs the receipt a second time in a temporary git worktree at `REF`, from the same relative directory. Use `HEAD` for uncommitted work and `HEAD~1` after you commit. The worktree is removed afterwards.
- `keep=PATH[,PATH]` copies files from the current tree into that worktree first. Use it when the test is part of the change. Without it, the baseline would only show that the test did not exist yet, so the verifier reports N/A and asks for `keep=`.
- `before=absent|present|SHA256` (on `file:`, `dir:`) records the pre-change state when no git ref has it.

Each receipt with a baseline gets one verdict:

| Verdict | Meaning | Counts as evidence |
| --- | --- | --- |
| PROVEN | fails before the change, passes after | yes |
| VACUOUS | passes before and after | no |
| BROKEN | fails after the change | no (the step fails) |
| N/A | no baseline possible (`http:`, `commit:`, `said:`, or the baseline run errored) | as without a baseline, never as PROVEN |

`--require-baseline` makes a done step PROVEN only when at least one behaviour receipt is PROVEN against its baseline and no receipt is VACUOUS.

Worked example: `calc.add()` returned `a - b`. The fix is in the working tree and not yet committed. `tests/test_smoke.py` is new in the change and always exits 0.

```markdown
- [x] 1. add() returns the sum
  - receipt: `cmd:python3 tests/test_add.py | baseline=HEAD`
  - receipt: `cmd:python3 tests/test_smoke.py | baseline=HEAD | keep=tests/test_smoke.py`
- [x] 2. The smoke test covers the fix
  - receipt: `cmd:python3 tests/test_smoke.py | baseline=HEAD | keep=tests/test_smoke.py`
```

```
$ python3 scripts/verify_receipts.py --ledger receipts.md
step 1 add() returns the sum
PASS  [1] cmd:python3 tests/test_add.py | baseline=HEAD -- exit 0; PROVEN: baseline HEAD: exit 1, expected 0; fails before the change, passes after (via python3)
VACUOUS  [2] cmd:python3 tests/test_smoke.py | baseline=HEAD | keep=tests/test_smoke.py -- exit 0; VACUOUS: baseline HEAD: exit 0; it passes before the change too, so it is not evidence (via python3)
  -> PROVEN: 2 receipt(s); behaviour checked through 1 instrument(s): python3; 1 failed before the change; receipt 2 VACUOUS, not counted
step 2 The smoke test covers the fix
VACUOUS  [3] cmd:python3 tests/test_smoke.py | baseline=HEAD | keep=tests/test_smoke.py -- exit 0; VACUOUS: baseline HEAD: exit 0; it passes before the change too, so it is not evidence (via python3)
  -> UNPROVEN: only VACUOUS behaviour receipts passed; a receipt that passes before the change is not evidence
summary: 3 pass, 0 fail; 1 of 2 done step(s) proven
baseline: 1 proven, 2 vacuous, 0 broken, 0 n/a
```

With `--require-baseline`, step 1 is also UNPROVEN (`receipt 2 VACUOUS: passes before the change too, so it is not evidence`): remove the smoke test from the claim or replace it with a test that can fail. Receipts with no `baseline=` or `before=` print exactly as before, so existing ledgers are unchanged.

## Limits

- **It is a skill, not a gate.** Nothing stops an agent from skipping it. Hook-based projects (see `references/prior-art.md`) enforce harder. The verifier's exit status can be wired into a hook or CI step if you want enforcement.
- **The verifier checks receipts, not whether they are the right receipts.** A passing `file:` receipt for a claim about live traffic is the wrong instrument, and the verifier cannot tell. A `- target:` line catches a receipt on the wrong object (`web-canary` for `web`) only when the step names its target; the match is on names, not on what the object really is. `proves=config` and `via=` are labels the agent applies honestly or not.
- **Instrument names are guessed from the receipt** (program name, HTTP host). Two different tools that read the same source look independent unless tagged with the same `via=`.
- **`http:` sends no credentials.** Authenticated endpoints need a `cmd:` receipt using a tool that reads credentials from the environment.
- **`sh:` receipts run arbitrary shell.** They are off unless `--allow-shell` is given. See `SECURITY.md`.
- **A baseline is only as good as the pre-change state it reaches.** `baseline=` sees tracked files at the ref plus anything in `keep=`. It does not see untracked build outputs, and it cannot rewind databases, services or anything outside the repository. A check that names a repository file by absolute path, or that finds a new test by discovery instead of by name, can be misjudged; prefer relative paths and name the test file. `before=` is a value you record, like `proves=config`.
- **No effect size is claimed yet.** The eval harness has been tested on four synthetic transcripts only. The with/without protocol has not been run on real model output.

## Related work

Several projects already do parts of this: evidence-before-claims prose skills, receipt-capturing Stop hooks, claim detectors calibrated on real transcripts, and probe runners. `references/prior-art.md` lists them with links and says honestly where this skill overlaps and where it differs.

## License

MIT. See `LICENSE`.
