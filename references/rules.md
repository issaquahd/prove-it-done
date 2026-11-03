# The six rules

Each rule below comes from a way that a "done" turned out to be false in practice. For each one: what the rule says, why it exists, how it usually gets broken, and what the verifier does about it.

## 1. A self-report is a claim, not evidence

**Rule.** Whatever a worker, sub-agent, tool or script says about its own success is a claim. That includes `RESULT=ok`, `exit 0`, "ok: updated", "Done!", and the step you remember finishing. Record it, then check the system yourself.

**Why.** The thing that did the work is the worst-placed witness to whether it worked. It reports what it *tried*, it may report success when an inner step failed and was swallowed, and it may be reporting on a different target than the one you meant. A worker that prints `RESULT=ok` after writing to the wrong file is still telling the truth about its own exit status.

**How it gets broken.**
- Relaying: "The worker finished, the change is live." The only evidence is the worker's message.
- Laundering: "Confirmed: the worker reports success." The word "confirmed" is attached to a self-report.
- Self-trust: you ran the command, saw no error, and wrote "done" without looking at the result.

**What the verifier does.** `said:` lines are printed as CLAIM and never counted. A step whose only lines are `said:` is UNPROVEN ("only self-reports"). A tool's own success output is not a receipt kind at all.

## 2. A confirmation names its instrument; two through the same instrument count as one

**Rule.** "Confirmed" or "verified" must say *how*: which command, endpoint, file, query or repo. When two confirmations go through the same instrument, they are one confirmation.

**Why.** An unnamed confirmation cannot be re-run, so it cannot be checked. Repeating one observation adds no independence: two `curl` calls through the same load balancer to the same stale cache agree with each other and are both wrong. Independence comes from different vantage points, not from more calls.

**How it gets broken.**
- "Verified, it works." (Verified with what?)
- "Checked twice, both fine": the same command run twice.
- Two tools that look different but read the same source, such as a dashboard and an API that both read the same metrics table.

**What the verifier does.** Every receipt is named by its kind and target, and the verifier prints the instrument it attributes to it. `--min-instruments N` needs N distinct instruments for a step to be PROVEN. `via=NAME` lets you say when two different-looking receipts share an instrument.

## 3. A config check is not a behaviour check

**Rule.** Reading what a system is *told* to do (a config file, a manifest, a desired-state record, a merged commit) does not show what it *does*. A behaviour claim needs a receipt that observes behaviour.

**Why.** The gap between configuration and behaviour is where many false "done"s live: the service was not restarted, the config was written to a path nothing reads, a later layer overrides it, the rollout is still in progress, the CDN serves the old page, the cron daemon has not picked up the new entry. Each of these passes a config check.

**How it gets broken.**
- "Set the timeout to 30s" backed by `grep timeout app.yaml`.
- "Deployed 2.1.0" backed by the manifest's image tag.
- "Published" backed by the commit that adds the page.

**What the verifier does.** Tag config receipts `| proves=config`. A done step whose passing receipts are all config receipts is UNPROVEN ("a config check is not a behaviour check"). The tag is yours to apply: the verifier cannot tell on its own whether a command reads config or behaviour.

## 4. A check that errors proves nothing

**Rule.** A check that could not complete is not a pass and not a fail. It is no information. Timeouts, refused connections, DNS failures, permission errors, 401s from the checker's own missing credentials, and "command not found" all leave the claim unproven.

**Why.** Error paths are where checks go to lie. A health script that catches every exception and prints "ok", a `curl` without `-f` that exits 0 on a 500, a grep that "finds nothing wrong" because the log file does not exist. Each turns "I could not look" into "I looked and it was fine".

**How it gets broken.**
- "The status check timed out, but the deploy reported success, so it is done."
- A check command whose exit status ignores the thing checked (`curl` without `-f`, `cmd || true`).
- Reading "no errors in the log" from a log that was empty because logging was broken.

**What the verifier does.** Any error in a check is FAIL with the words "a check that errors proves nothing". `http:` judges the status code itself rather than trusting an exit code. Use `contains=` to require positive evidence in the output instead of the absence of an error.

## 5. A check must come after the last change

**Rule.** A receipt is about the system at the moment it ran. If you changed anything after that (another edit, a restart, a redeploy, a rollback), the receipt is stale and you run the checks again.

**Why.** Agents often verify, then make "one small fix", then report the earlier verification. The last change is the one most likely to break something, because it gets the least attention.

**How it gets broken.**
- Test, tweak, report the test result from before the tweak.
- Check staging, deploy a hotfix, report the staging check.
- Verify a config, restart the service (which rewrites the config), report the config check.

**What the verifier does.** It runs every receipt now, so a verifier run that comes last is fresh by construction. The skill's step 5 makes the verifier run the last action before the report. Transcript scorers (see `evals/run.md`) measure this rule from the outside: a claim with no check after the last change is flagged.

## 6. Reopen, never delete

**Rule.** When a receipt fails, or turns out to be weaker than the claim it backed, the step is reopened: the done line is struck through with the date and the reason, and an open line is added. Nothing is erased.

**Why.** Deleting a false "done" hides the fact that it was ever claimed, which hides the pattern: which kinds of claims tend to be false, which workers over-report, which receipts are too weak. A struck-through line is cheap, and it keeps the record honest for the next reader, who may be you after a context reset.

**How it gets broken.**
- Editing the done line to say something weaker, so it still looks done.
- Removing a failing receipt so the step passes.
- Replacing the claim's wording after the fact.

**What the verifier does.** `--reopen` rewrites each unproven done step into `- ~~[x] N. claim~~ reopened DATE: reason` plus a fresh `- [ ] N. claim`, and keeps every receipt line. If a receipt was wrong, change the claim to match what the receipt can prove, and say so in your report.

## Related to rules 4 and 5: a receipt must be able to fail

**Habit.** Before a passing receipt counts as evidence of a change, show that it fails without the change.

**Why.** A check that cannot fail tells you nothing about the change. A test that always exits 0, a `contains=` that matches text which was already there, a `file:` that existed before: each passes after the change and would have passed without it. Training pipelines for coding agents found the same problem in their graders and now run every grader on an empty patch, which must fail (Sandman, arXiv 2610.39711).

**How it gets broken.**
- Writing a new test in the same change and counting it as proof, when it would pass on the old code too.
- A `contains=` value that appears in the output both before and after.
- Checking that a file exists when it existed before the change.

**What the verifier does.** `| baseline=REF` re-runs `cmd:`, `sh:`, `file:` and `dir:` receipts in a git worktree at `REF`, and `| before=` records a file's pre-change state. A receipt that passes before and after is VACUOUS and does not count. `--require-baseline` makes a done step need a receipt that failed before the change. Details are in `receipts.md`.

## A seventh habit: size the claim to the receipt

Not a rule the verifier enforces, but the one that makes the others easy: say exactly what the receipts show. "The version endpoint on staging returns 2.1.0" is a claim a receipt can prove. "The release went well" is not. If the receipt you can write is narrower than the claim you wanted to make, narrow the claim.
