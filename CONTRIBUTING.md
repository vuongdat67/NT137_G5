# Contributing

## Development Setup

1. Create and activate virtual environment
2. Install dependencies
3. Run tests before commit

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
pytest -q
```

## Commit Guidelines

- Use clear, scoped commit messages
- Keep changes focused and small
- Update docs/changelog when behavior changes

## Pull Request Checklist

- [ ] Tests pass locally
- [ ] New behavior documented in `README.md` or `docs/`
- [ ] `CHANGELOG.md` updated
- [ ] No secrets committed

## Security Note

Do not commit live malware samples, secrets, or API keys.
