# SudoScopeAudit

Snapshot sudoers include and alias scope audit. A complete independent new-scope defensive project; upstream-wide rewriting and equivalence are not claimed.

Input: `{ "entry": "/etc/sudoers", "files": {"/etc/sudoers": "sudoers text"} }`. All includes are resolved against the supplied map, never the filesystem. Includedir follows lexical order and skips dot/tilde filenames. User/Host/Runas/Cmnd aliases support forward references with cycle/depth/10000-expansion limits. The complete frozen 344-basename risk catalog is included under the original BSD notice. Checks cover subject/host/runas ALL, password/environment tags (including inheritance), dangerous command names, writable-looking paths, wildcard scope and global Defaults. Negation, missing includes/aliases, scoped Defaults, digests, command regexes and multi-host segments are OPEN. Findings flag declared risk for review, not proof that a user can escalate privileges. Valid narrow grants may PASS only the stated static scope. Complete effective authorization is OPEN.

## Use

Install the wheel in `artifacts/`, then run `sudo-scope-audit examples/good.json`. Or use `python -m sudo_scope_audit examples/good.json`. JSON input is limited to 2 MiB, 32 nesting levels and 100000 nodes; duplicate keys, non-finite values, changed files, symlinks and non-regular files are rejected. Findings are capped at 20000. No network requests, host collection, policy changes or shell execution occur.

## Output and verification

Each finding includes check, PASS/FAIL/OPEN, evidence location and explanation. Overall status is FAIL if a check fails; otherwise OPEN for incomplete/unsupported input; otherwise PASS for only this declared static scope. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. See `examples/expectations.json`, `tests/`, `VALIDATION.md`, `ORIGIN.md`, `NOTICE` where present, and exact `artifacts/validation.json`.

Snapshot results do not prove runtime security, actual authorization, upstream equivalence or CVP qualification/approval.


The file CLI requires non-following, non-blocking descriptor support (`O_NOFOLLOW` and `O_NONBLOCK`). Missing capabilities return controlled ERROR without weakening safe-file reads. This profile targets capable macOS/Linux environments; native Windows file-CLI behavior has not been verified. Windows observations remain supplied JSON data.
