# Setup Environment

## 1. Prerequisites

- Python 3.11+
- Git
- Windows PowerShell (recommended on Windows)

## 2. Clone and enter repository

```powershell
git clone <your-repo-url>
cd code
```

## 3. Create and activate virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## 4. Install dependencies

```powershell
pip install --upgrade pip
pip install -e ".[dev]"
```

Alternative:

```powershell
pip install -r requirements.txt
```

## 5. Verify installation

```powershell
pytest -q
python main.py gui
```

## 6. Optional configuration

- Copy sample config:

```powershell
Copy-Item ..\config.yaml.example .\config.yaml
```

- `config.yaml` is loaded automatically at startup from `code/config.yaml`.
- Set `bazaar_api_key` in that file to persist MalwareBazaar auth across runs.
- Environment variables still take precedence, for example:

```powershell
setx MSA_BAZAAR_API_KEY "<your-api-key>"
```

- Optional: set `MSA_CONFIG_FILE` to point to a custom config path.

## 7. Common paths

- Runtime DB: `output/analyzer.db`
- Downloaded ZIP samples: configurable in Intel tab
- Local sample folder default: `malware_samples/`
