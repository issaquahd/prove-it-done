# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Command-line usage errors now identify missing and invalid values for `--timeout`, `--min-instruments`, and `--ledger`.

## [0.1.0] - 2026-10-11

### Added

- `SKILL.md`: seven steps for receipt-gated completion, and the six rules.
- `scripts/verify_receipts.py`: re-runs receipts and prints PASS, FAIL or CLAIM for each. Kinds `cmd:` (no shell), `sh:` (opt-in with `--allow-shell`), `file:` (exists, `sha256=`), `dir:`, `http:` (`status=`, `contains=`), `commit:` (`repo=`, `path=`, `branch=`), and `said:` (recorded self-report, never counted). Ledger mode with per-step verdicts, `proves=config` tagging, instrument counting with `--min-instruments`, `--reopen` with strike-through, and `--list`. Output is redacted and never includes command output.
- `references/`: receipt format, the rules in depth, and a prior-art survey.
- `examples/`: a deploy, a config change, a published page, and a worker whose "ok" was false.
- `evals/`: eight test prompts, a transcript scorer built on the Agent Trace Clinic's `unproven_completion` detector, four synthetic transcripts, and a with/without protocol.
- Unit tests, and a CI workflow for Linux, macOS and Windows.
