# Code audit report

**57 findings in 9 files (1 critical, 17 high, 18 medium, 21 low)**

| Severity | Count |
|---|---|
| 🟥 critical | 1 |
| 🟧 high | 17 |
| 🟨 medium | 18 |
| 🟦 low | 21 |
| ⬜ info | 0 |

| Category | Count |
|---|---|
| Security issues | 20 |
| Slop (AI-style junk & dead code) | 20 |
| Coding gaps & loose ends | 17 |

## Security issues (20)

| Sev | Rule | Location | Message |
|---|---|---|---|
| 🟥 critical | `SEC001` | `app/db.py:10` | AWS access key committed to source. Rotate it and load from a secret store. |
| 🟧 high | `SEC009` | `.env` | '.env' looks like an environment/key file. Remove it from version control and add it to .gitignore. |
| 🟧 high | `SEC002` | `app/db.py:9` | Credential-like value assigned a string literal. Load it from the environment or a secret manager. |
| 🟧 high | `SEC005` | `app/db.py:15` | SQL assembled from strings is injectable. Use parameterised queries. |
| 🟧 high | `SEC005` | `app/db.py:20` | SQL assembled from strings is injectable. Use parameterised queries. |
| 🟧 high | `SEC007` | `app/db.py:28` | Deserializing untrusted data can execute code. Use a data-only format (JSON) or a safe loader. |
| 🟧 high | `SEC008` | `app/db.py:32` | Disabling certificate verification enables man-in-the-middle attacks. |
| 🟧 high | `SEC004` | `app/service.py:9` | subprocess call with shell=True. Pass an argument list and drop shell=True. |
| 🟧 high | `SEC003` | `app/service.py:13` | eval() on non-literal input allows arbitrary code execution. |
| 🟧 high | `SEC008` | `cmd/main.go:11` | Disabling certificate verification enables man-in-the-middle attacks. |
| 🟧 high | `SEC010` | `requirements.txt:1` | requests 2.25.0 is below 2.31.0 (CVE-2023-32681 proxy credential leak). Upgrade and run `pip-audit` for a full check. |
| 🟧 high | `SEC010` | `web/package.json:6` | lodash 4.17.15 is below 4.17.21 (CVE-2021-23337 command injection). Upgrade and run `npm audit` for a full check. |
| 🟧 high | `SEC010` | `web/package.json:7` | axios 0.21.1 is below 1.6.0 (CVE-2023-45857 CSRF token leak). Upgrade and run `npm audit` for a full check. |
| 🟧 high | `SEC008` | `web/server.js:7` | Disabling certificate verification enables man-in-the-middle attacks. |
| 🟧 high | `SEC002` | `web/server.js:8` | Credential-like value assigned a string literal. Load it from the environment or a secret manager. |
| 🟧 high | `SEC004` | `web/server.js:11` | Command built from strings and run through a shell. Use an argument list API. |
| 🟧 high | `SEC003` | `web/server.js:16` | eval on dynamic input allows arbitrary code execution. |
| 🟧 high | `SEC005` | `web/server.js:20` | SQL assembled from strings is injectable. Use parameterised queries. |
| 🟨 medium | `SEC006` | `app/db.py:24` | MD5/SHA-1/DES/RC4/ECB are broken for security purposes. Use SHA-256+, AES-GCM, bcrypt/argon2. |
| 🟦 low | `SEC010` | `web/package.json:5` | 'express' is unpinned; builds are not reproducible and may pull a vulnerable release. |

## Slop (AI-style junk & dead code) (20)

| Sev | Rule | Location | Message |
|---|---|---|---|
| 🟨 medium | `SLP005` | `app/db.py:7` | 'fastjsonx' is not stdlib, not a local module, and not declared in any dependency manifest. It may be hallucinated, misspelled, or missing from requirements. |
| 🟨 medium | `SLP002` | `app/service.py:4` | Text pasted from a chat assistant (or a stray markdown fence) inside source code. |
| 🟨 medium | `SLP008` | `app/service.py:28` | Interactive debugger hook left in code; it will hang or leak data in production. |
| 🟨 medium | `SLP001` | `app/utils.py:6` | Placeholder text left in shipped code; the logic it describes probably does not exist. |
| 🟨 medium | `SLP010` | `app/utils.py:27` | Statement after `return` can never run (dead code). |
| 🟨 medium | `SLP001` | `app/utils.py:31` | Placeholder text left in shipped code; the logic it describes probably does not exist. |
| 🟨 medium | `SLP001` | `app/utils.py:32` | Placeholder text left in shipped code; the logic it describes probably does not exist. |
| 🟨 medium | `SLP005` | `web/server.js:3` | 'super-fast-validator' is imported but not listed in package.json. It may be hallucinated or missing from dependencies. |
| 🟦 low | `SLP006` | `app/db.py:1` | 'os' is imported but never used. |
| 🟦 low | `SLP006` | `app/db.py:2` | 'json' is imported but never used. |
| 🟦 low | `SLP009` | `app/db.py:47` | Print-style debugging in library code. Use a logger or remove it. |
| 🟦 low | `SLP006` | `app/utils.py:1` | 're' is imported but never used. |
| 🟦 low | `SLP006` | `app/utils.py:2` | 'datetime' is imported but never used. |
| 🟦 low | `SLP003` | `app/utils.py:23` | Comment only repeats what the next line says; explain *why* or delete it. |
| 🟦 low | `SLP003` | `app/utils.py:25` | Comment only repeats what the next line says; explain *why* or delete it. |
| 🟦 low | `SLP009` | `app/utils.py:27` | Print-style debugging in library code. Use a logger or remove it. |
| 🟦 low | `SLP009` | `app/utils.py:33` | Print-style debugging in library code. Use a logger or remove it. |
| 🟦 low | `SLP007` | `app/utils.py:34` | 4 lines of commented-out code. Version control remembers it; delete it. |
| 🟦 low | `SLP004` | `app/utils.py:42` | Block duplicates app/service.py:17. Extract a shared function. |
| 🟦 low | `SLP009` | `web/server.js:15` | Print-style debugging in library code. Use a logger or remove it. |

## Coding gaps & loose ends (17)

| Sev | Rule | Location | Message |
|---|---|---|---|
| 🟨 medium | `GAP004` | `.` | No test files found for 4 source modules. |
| 🟨 medium | `GAP005` | `.` | No README: nobody knows what this is or how to run it. |
| 🟨 medium | `GAP002` | `app/db.py:39` | Exception is caught and silently ignored. Log it, handle it, or let it propagate. |
| 🟨 medium | `GAP006` | `app/utils.py:5` | `normalize_email()` has no implementation (only pass/.../docstring). |
| 🟨 medium | `GAP006` | `app/utils.py:10` | `calculate_discount()` has no implementation (only pass/.../docstring). |
| 🟨 medium | `GAP007` | `cmd/main.go:13` | Returned error is assigned to `_` and ignored. |
| 🟨 medium | `GAP007` | `cmd/main.go:14` | Returned error is assigned to `_` and ignored. |
| 🟨 medium | `GAP002` | `cmd/main.go:16` | Error is caught and silently ignored. |
| 🟨 medium | `GAP002` | `web/server.js:23` | Error is caught and silently ignored. |
| 🟦 low | `GAP005` | `.` | No .gitignore: build output and secrets are easy to commit by accident. |
| 🟦 low | `GAP005` | `.` | No LICENSE: the code is legally unusable by others. |
| 🟦 low | `GAP008` | `app/db.py:32` | HTTP call has no timeout and can hang forever. |
| 🟦 low | `GAP003` | `app/db.py:46` | Bare `except:` also catches KeyboardInterrupt/SystemExit. Catch a specific exception. |
| 🟦 low | `GAP001` | `app/service.py:8` | FIXME marker: # FIXME: this breaks when name has spaces |
| 🟦 low | `GAP001` | `app/service.py:26` | HACK marker: # HACK: skip validation until the schema is final |
| 🟦 low | `GAP006` | `app/utils.py:15` | `send_invoice()` only raises NotImplementedError. |
| 🟦 low | `GAP006` | `web/server.js:26` | Function body is empty or only throws 'not implemented'. |

_Generated by audit-agent 0.1.0; 30 rules; LLM triage: off._
