# Security

## What the verifier can do

`scripts/verify_receipts.py` runs whatever the receipts in a ledger tell it to run. Treat a ledger like a script.

- **`cmd:` receipts** run a program with arguments, without a shell (`subprocess.run(argv, shell=False)`). Pipes, redirects, `;`, `&&`, globbing and variable expansion do not happen; those characters are passed to the program as plain arguments. The program still runs with your user's permissions and environment, so a `cmd:` receipt can do anything that program can do (`cmd:rm -rf build` deletes `build`).
- **`sh:` receipts** run a string through the system shell (`shell=True`: `/bin/sh` on POSIX, `cmd.exe` on Windows). This allows command injection by design: whoever wrote the receipt can run anything. The verifier refuses `sh:` receipts unless it is started with `--allow-shell`. Pass that flag only for ledgers whose every `sh:` line you wrote or reviewed. On POSIX, a timed-out `sh:` receipt kills the shell but may leave its children running.
- **`http:` receipts** make one GET request to an `http` or `https` URL, following redirects only to `http` or `https` URLs, with Python's default TLS verification, no cookies and no credentials. Other URL schemes are refused. A receipt can still point at internal addresses reachable from your machine (for example cloud metadata endpoints), so review URLs in ledgers you did not write.
- **`commit:` receipts** run read-only git commands (`cat-file`, `show`, `merge-base`). The hash must be hex and a `branch=` value may not start with `-`, so receipts cannot inject git options.
- **`file:` and `dir:` receipts** only read metadata and file contents (for `sha256=`).
- **`baseline=REF`** runs the receipt a second time, in a temporary detached git worktree created under the system temp directory. The verifier runs `git worktree add` with repository hooks disabled, copies any `keep=` paths into it, and removes it with `git worktree remove --force` and `git worktree prune` afterwards. The ref may not start with `-` or contain whitespace. A `cmd:` or `sh:` receipt with a baseline runs twice, so it should be safe to run twice.

Every receipt runs with standard input closed and a timeout (default 60 seconds, `--timeout` or `| timeout=S`).

**Do not run the verifier on a ledger from an untrusted source**, the same way you would not run its shell script. Use `--list` to read what a ledger would run without running anything.

## Secrets

- The verifier never prints command output (stdout or stderr), HTTP response bodies, or file contents.
- Every printed line goes through a redactor that masks credentials in URLs (`user:pass@`, `?token=`, `?api_key=`), secret-named flags (`--password=`, `--api-key VALUE`), `Authorization` and `Bearer` values, `NAME_TOKEN=value`-style assignments, and common token shapes (GitHub, GitLab, Slack, AWS access keys, `sk-` keys).
- The redactor is a safety net, not a guarantee. **Keep secrets out of receipts.** Read them from the environment inside the program a `cmd:` receipt runs, and never put a secret in a `contains=` value: the receipt line itself is printed.
- Ledgers are plain files and are often committed. Anything in a receipt is as public as the ledger.

## Reporting a vulnerability

Please report security problems privately through GitHub's "Report a vulnerability" (private security advisory) on this repository, rather than in a public issue. Include the receipt or ledger that triggers the problem, what you expected, and what happened. You should get an acknowledgement within a week.

Issues in scope: a receipt that causes the verifier to run something other than what its kind documents (for example shell execution from a `cmd:` receipt), a secret printed despite matching a documented redaction pattern, git option injection, a check that reports PASS when it errored, or a baseline reported PROVEN when the baseline run errored.
