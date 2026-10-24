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

**Examples.** `examples/` has four worked ledgers with verifier output: a deploy, a config change, a published page, and a worker whose "ok" was false.

**Measure it.** `evals/evals.json` has eight test prompts. `evals/run.md` describes a with/without comparison scored by a deterministic unproven-completion detector, and shows the scorer working on four synthetic transcripts.

**Test.** `python3 -m unittest discover -s tests`. `.github/workflows/ci.yml` runs the same tests on Linux, macOS and Windows once the repository is on GitHub.

## Limits

- **It is a skill, not a gate.** Nothing stops an agent from skipping it. Hook-based projects (see `references/prior-art.md`) enforce harder. The verifier's exit status can be wired into a hook or CI step if you want enforcement.
- **The verifier checks receipts, not whether they are the right receipts.** A passing `file:` receipt for a claim about live traffic is the wrong instrument, and the verifier cannot tell. `proves=config` and `via=` are labels the agent applies honestly or not.
- **Instrument names are guessed from the receipt** (program name, HTTP host). Two different tools that read the same source look independent unless tagged with the same `via=`.
- **`http:` sends no credentials.** Authenticated endpoints need a `cmd:` receipt using a tool that reads credentials from the environment.
- **`sh:` receipts run arbitrary shell.** They are off unless `--allow-shell` is given. See `SECURITY.md`.
- **No effect size is claimed yet.** The eval harness has been tested on four synthetic transcripts only. The with/without protocol has not been run on real model output.

## Related work

Several projects already do parts of this: evidence-before-claims prose skills, receipt-capturing Stop hooks, claim detectors calibrated on real transcripts, and probe runners. `references/prior-art.md` lists them with links and says honestly where this skill overlaps and where it differs.

## License

MIT. See `LICENSE`.
- Nature v0.1 confirmed live 2026-10-24 by Gherkin-lite
