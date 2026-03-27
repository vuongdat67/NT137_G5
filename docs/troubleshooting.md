# Troubleshooting

## GUI fails to start with SyntaxError

- Run:

```powershell
pytest -q
python main.py gui
```

- If error points to a recent edit, pull latest branch or revert broken local changes.

## Intel download fails with UTF-8 decode errors

This was caused by trying to parse binary ZIP responses as JSON.
Current code handles ZIP signature first.
Update to latest branch and retry.

## Intel shows updated=0 and skipped>0

Likely hashes are not yet in local DB.

Fix:

1. Enable `Auto-scan after download` in Intel tab, or
2. Scan downloaded ZIP files manually first

## ZIP extraction cleanup errors on Windows

Windows may hold temporary file handles briefly.
Scanner uses tolerant cleanup with retries.
If issue persists, retry scan after a short delay.

## Tests are not discovered from root

Run tests from repository folder containing `pyproject.toml`:

```powershell
cd code
pytest -q
```

## Cannot push to GitHub

- Verify remote:

```powershell
git remote -v
```

- Verify authentication (PAT/credential manager)
- Push current branch explicitly:

```powershell
git push -u origin <branch>
```
