# vuln-demo-python

A deliberately vulnerable Python (Flask) project for testing security scanners. **Never deploy or run it.**
`app.py` passes a syntax check (`python -m py_compile`) but has not been run. The files `.env`,
`config.yaml` and `settings.ini` hold fake passwords on purpose, so they are not git-ignored.

Contents: `requirements.txt` (9 pinned old packages), `app.py` (14 planted flaw locations),
`config.yaml`, `.env`, `settings.ini` (hard-coded passwords), `Dockerfile`.

## Code findings a scanner should report (`app.py`)

| CWE | Name | Line |
|---|---|---|
| CWE-798 | Hard-coded Credentials (`app.secret_key`) | 12 |
| CWE-798 | Hard-coded Credentials (`DB_PASSWORD`) | 14 |
| CWE-89 | SQL Injection (f-string in `sqlite3` query) | 21 |
| CWE-78 | OS Command Injection (`shell=True`) | 28 |
| CWE-22 | Path Traversal (`send_file`) | 33 |
| CWE-79 | Cross-site Scripting (HTML built from a parameter) | 38 |
| CWE-95 | Eval Injection (`eval` of a request parameter) | 43 |
| CWE-918 | Server-Side Request Forgery (`requests.get` of a user URL) | 48 |
| CWE-295 | Improper Certificate Validation (`verify=False`) | 48 |
| CWE-601 | Open Redirect | 54 |
| CWE-502 | Deserialization of Untrusted Data (`pickle.loads`) | 59 |
| CWE-502 | Deserialization of Untrusted Data (`yaml.load` with `yaml.Loader`) | 64 |
| CWE-328 | Use of Weak Hash (MD5; CWE-916 is also a good label because it hashes a password) | 68 |
| CWE-347 | Improper Verification of Cryptographic Signature (`verify_signature: False`) | 72 |
| CWE-489 | Active Debug Code (`debug=True`) | 76 |

## Configuration findings (the file types earlier scanners missed)

| CWE | File and line |
|---|---|
| CWE-798 | `config.yaml:4` (`password`) |
| CWE-798 | `.env:1` (`DB_PASSWORD`) and `.env:2` (`SECRET_KEY`) |
| CWE-798 | `settings.ini:3` (`password`) |

Optional (only if the scanner checks Dockerfiles): `Dockerfile:1` uses `python:3.8`, which is end-of-life
(CWE-1104), and the image never sets a `USER`, so it runs as root (CWE-250).

## Dependency findings a scanner should report

`EXPECTED-DEPENDENCY-FINDINGS.csv` lists **46 GHSA advisories** (3 critical, 14 high, 27 medium, 2 low),
checked against GitHub's advisory database. The most important:

| Package | GHSA | CVE | Severity | CWE | Fixed in |
|---|---|---|---|---|---|
| PyYAML 5.3 | GHSA-6757-jp84-gxfx | CVE-2020-1747 | critical | 20 | 5.3.1 |
| PyYAML 5.3 | GHSA-8q59-q68h-6hv4 | CVE-2020-14343 | critical | 20 | 5.4 |
| PyJWT 1.7.1 | GHSA-ffc3-869f-jxw9 | CVE-2026-102268 | critical | 347 | 2.14.0 |
| PyJWT 1.7.1 | GHSA-ffqj-6fqr-9h24 | CVE-2022-29217 | high | 327 | 2.4.0 |
| Flask 2.0.1 | GHSA-m2qf-hxjv-5gpq | CVE-2023-30861 | high | 539 | 2.2.5 |
| Werkzeug 2.0.1 | GHSA-2g68-c3qc-8985 | CVE-2024-34069 | high | 352 | 3.0.3 |
| Werkzeug 2.0.1 | GHSA-xg9f-g7g7-2323 | CVE-2023-25577 | high | 400, 770 | 2.2.3 |
| requests 2.19.1 | GHSA-x84v-xcm2-53pg | CVE-2018-18074 | high | 522 | 2.20.0 |
| urllib3 1.23 (indirect) | GHSA-mh33-7rrq-662w | CVE-2019-11324 | high | 295 | 1.24.2 |
| urllib3 1.23 (indirect) | GHSA-v845-jxx5-vc9f | CVE-2023-43804 | high | 200 | 1.26.17 |

Per package: urllib3 12, Werkzeug 10, PyJWT 8, requests 5, Jinja2 5, PyYAML 2, Flask 2, idna 2.
MarkupSafe, itsdangerous and click have none.

## Indirect dependencies (14 of the 46)
`requirements.txt` does not pin what `requests` pulls in. Its version limits (`urllib3<1.24`, `idna<2.8`)
resolve to **urllib3 1.23** (12 advisories) and **idna 2.7** (2 advisories). A scanner that only reads
`requirements.txt` will miss all 14. `chardet 3.0.4` and `certifi` have no advisories.

## Notes
- Advisory counts can grow after 2026-10-20 as new advisories are published.
- Some code scanners label a flaw with a neighbouring CWE (for example CWE-77 for command injection,
  CWE-327 for MD5, CWE-1336 for template-style XSS). Treat the tables as the expected set, not the
  only acceptable numbers.
