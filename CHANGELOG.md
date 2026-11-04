# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Claimed target: a done step can name its object with `- target: NAME` (or `--target NAME` on the command line). Only behaviour receipts about NAME count, matched on whole words, so a check on `web-canary` does not prove a claim about `web`. `- target: NAME | needs=sha256` also needs a passing `file:` receipt on NAME with `sha256=`, so a listing (name and size) is not enough. A receipt option `target=NAME` names the object a receipt is about; the receipt FAILs when its check does not read NAME. Steps without a target line are judged as before.
- Baseline check (fail before, pass after): `baseline=REF` re-runs a `cmd:`, `sh:`, `file:` or `dir:` receipt in a temporary git worktree at `REF`, with `keep=PATH[,PATH]` to carry a new test into it; `before=absent|present|SHA256` records the pre-change state of a `file:` or `dir:`. Each such receipt gets a verdict: PROVEN (fails before, passes after), VACUOUS (passes before and after; not counted as evidence), BROKEN (fails after) or N/A (`http:`, `commit:`, `said:`, or the baseline run errored; never counted as a baseline). A new test that is missing at `REF` without `keep=` is N/A, not PROVEN. `--require-baseline` makes a done step PROVEN only with at least one PROVEN behaviour receipt and no VACUOUS one. Based on the empty-patch grader check in Sandman (arXiv 2610.39711). Receipts without these options behave and print as before.

### Changed

- `sha256=` on a receipt that is not `file:` is now a parse error. Before, `cmd:`, `dir:` and `http:` receipts ignored it and could pass without any checksum.

## [0.1.0] - 2026-10-11

### Added

- `SKILL.md`: seven steps for receipt-gated completion, and the six rules.
- `scripts/verify_receipts.py`: re-runs receipts and prints PASS, FAIL or CLAIM for each. Kinds `cmd:` (no shell), `sh:` (opt-in with `--allow-shell`), `file:` (exists, `sha256=`), `dir:`, `http:` (`status=`, `contains=`), `commit:` (`repo=`, `path=`, `branch=`), and `said:` (recorded self-report, never counted). Ledger mode with per-step verdicts, `proves=config` tagging, instrument counting with `--min-instruments`, `--reopen` with strike-through, and `--list`. Output is redacted and never includes command output.
- `references/`: receipt format, the rules in depth, and a prior-art survey.
- `examples/`: a deploy, a config change, a published page, and a worker whose "ok" was false.
- `evals/`: eight test prompts, a transcript scorer built on the Agent Trace Clinic's `unproven_completion` detector, four synthetic transcripts, and a with/without protocol.
- Unit tests, and a CI workflow for Linux, macOS and Windows.

[Unreleased]: https://github.com/issaquahd/prove-it-done/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/issaquahd/prove-it-done/releases/tag/v0.1.0
