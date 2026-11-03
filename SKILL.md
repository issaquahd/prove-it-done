---
name: prove-it-done
description: 'Saying done, fixed, deployed, live, or a worker said ok? Prove it: write one receipt per claim (command, file hash, HTTP status, git commit), re-run them with the bundled verifier against the real system after the last change, report only what passed, and reopen any step whose receipt fails.'
license: MIT
---

# Prove it done

"Done" is a claim about the world. This skill makes every completion claim carry a **receipt**: a one-line check that anyone can re-run against the real system, now, and get the same answer. The bundled verifier, `scripts/verify_receipts.py`, re-runs receipts and prints PASS or FAIL for each. It reads no transcript and trusts nobody's word.

Use it whenever you are about to tell someone that work is finished: a deploy, a config change, a published page, a merged fix, a file written, or a task a sub-agent or worker says it completed.

## The rules

1. **A self-report is a claim, not evidence.** A worker's `RESULT=ok`, a tool's "ok: updated", a sub-agent's "done", and your own memory of having done it are all claims. Record them, but never count them.
2. **A confirmation names its instrument.** "Confirmed" means nothing until it says *how*: which command, endpoint, file or repo. Two confirmations through the same instrument count as one.
3. **A config check is not a behaviour check.** A file that says `ttl: 300` proves the file says it. Whether the running system uses 300 is a separate claim, and it needs a receipt that observes the system.
4. **A check that errors proves nothing.** A timeout, a refused connection, a 401, or "command not found" is neither PASS nor proof of failure. The claim is unproven until a check actually completes.
5. **A check must come after the last change.** A receipt that ran before your final edit, restart or deploy is about a system that no longer exists. Change anything, and you run the checks again.
6. **Reopen, never delete.** When a receipt turns out weaker than the claim, or fails, strike the done line through, state why, and add an open line. The history of what was claimed stays visible.

The reasoning and the common ways each rule gets broken are in `references/rules.md`.

## Steps

### 1. List the claims

Before you write any "done", list each thing you are about to say is true, one per line, as an observable fact about the system: "staging serves version 2.1.0", not "deployed the release".

Done when: every claim names a system state that someone else could observe, and the list contains no claims that merely restate an action you took ("ran the deploy").

### 2. Pick an instrument for each claim

For each claim, choose the most direct way to observe it. Prefer what users or other systems see (an HTTP response, a query result, a service's effective config) over what you wrote (a file, a manifest, a commit). See `references/receipts.md` for which receipt kind fits which claim.

Done when: every claim has at least one receipt that checks behaviour, and every receipt names its instrument (the kind and target do this; add `| via=NAME` when two receipts would otherwise look like different instruments but are not).

### 3. Write the receipts in a ledger

Use one Markdown file per task (for example `receipts.md`). Each step is a numbered checkbox. Each receipt is an indented line with the spec in backticks:

```markdown
- [x] 1. Staging serves web 2.1.0
  - receipt: `http:https://staging.example.com/version | status=200 | contains=2.1.0`
  - receipt: `cmd:kubectl -n staging get deploy web -o jsonpath={..image} | contains=web:2.1.0 | proves=config`
```

Kinds: `cmd:` (argv, no shell), `sh:` (shell string, needs `--allow-shell`), `file:` (exists, optional `sha256=`), `dir:`, `http:` (status, optional `contains=`), `commit:` (exists, optional `path=`, `branch=`), and `said:` for recording a self-report. Tag receipts that only read configuration or desired state with `| proves=config`.

For a code change, show that the receipt can fail: add `| baseline=HEAD` (or `HEAD~1` once committed) so the verifier also runs it against the pre-change tree, and `| keep=PATH` when the test itself is new. A receipt that passes before the change too is VACUOUS and does not count. For a `file:` or `dir:` with no git history, record `| before=absent` or the old SHA-256. Use `--require-baseline` when a claim must rest on a receipt that failed before the change.

Done when: `python3 scripts/verify_receipts.py --ledger receipts.md --list` prints every step and receipt with no parse error.

### 4. Record self-reports as `said:`, then go and check

When a worker, sub-agent or tool reports success, write it down as `said:` and add a receipt that checks the system yourself:

```markdown
  - receipt: `said:worker-2 reported RESULT=ok`
  - receipt: `cmd:logctl show-policy app | contains=keep=7`
```

The verifier prints `said:` lines as CLAIM and never counts them. A step with only `said:` lines is unproven.

Done when: no done step relies on a `said:` line alone.

### 5. Make your last change, then run the verifier

Finish every edit, restart and deploy first. Then run:

```
python3 scripts/verify_receipts.py --ledger receipts.md
```

Add `--min-instruments 2` for claims that matter enough to need two independent observations. Add `--allow-shell` only for `sh:` receipts you wrote yourself (see `SECURITY.md`).

Done when: the verifier exits 0, its summary says every done step is PROVEN, and you made no change after it ran. If you changed anything after it ran, run it again.

### 6. On FAIL, reopen the step instead of arguing with it

If a receipt fails, errors, or a step is UNPROVEN, the claim is not true yet. Run:

```
python3 scripts/verify_receipts.py --ledger receipts.md --reopen
```

This strikes through the done line (`- ~~[x] 1. ...~~ reopened DATE: reason`) and adds a fresh open line below it. Nothing is deleted. Then fix the system, not the receipt. Weaken a receipt only if the claim was wrong, and if you do, narrow the claim to match.

Done when: every failing step shows a struck-through line with a reason and an open line, and the original receipt lines are still present.

### 7. Report exactly what the receipts prove

In your final message:

- say "done" only for PROVEN steps, and quote the receipt that proves each one;
- say plainly which steps are not done, and why (failed, errored, config only, self-report only);
- when a worker's report turned out false, say so.

Done when: every completion word in your message ("done", "fixed", "deployed", "live", "verified") maps to a PROVEN step in the ledger, and every unproven step is named as not done.

## Without a filesystem

If you cannot write a ledger, pass receipts on the command line:

```
python3 scripts/verify_receipts.py 'http:https://example.com/ | status=200' 'commit:4f2a9c1 | repo=. | branch=main'
```

Every receipt must pass for exit 0. If you cannot run the verifier at all, do the same checks with your own tools after the last change, quote each result with its instrument, and say that the verifier was not run.

## What this does not do

- It cannot tell whether a receipt is the *right* check for the claim. A passing `file:` receipt for a claim about traffic is still the wrong instrument. Steps 1 and 2 are where that is decided.
- It does not see your transcript. Use a trace scorer (see `evals/run.md`) to measure whether claims were checked.
- `proves=config` is a label you apply. The verifier cannot detect a config check on its own.

## Files

Paths in this file are relative to the skill directory.

- `scripts/verify_receipts.py`: the verifier (Python 3.9+, standard library only).
- `references/receipts.md`: receipt format, every kind and option, and which kind fits which claim.
- `references/rules.md`: the six rules, why each exists, and how each gets broken.
- `references/prior-art.md`: related skills and tools, and how this one differs.
- `examples/`: four worked ledgers (a deploy, a config change, a published page, a worker whose "ok" was false).
- `evals/`: test prompts, and a harness that scores transcripts with and without the skill.
