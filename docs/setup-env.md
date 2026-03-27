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

- Update API key in GUI `Intel` tab for MalwareBazaar operations.

## 7. Common paths

- Runtime DB: `output/analyzer.db`
- Downloaded ZIP samples: configurable in Intel tab
- Local sample folder default: `malware_samples/`
