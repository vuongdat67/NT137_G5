# Setup Environment

## 1. Prerequisites

- Python 3.11+
- Git

## 2. Clone repository

```bash
git clone <your-repo-url>
cd NT137_G5
```

## 3. OS-specific setup

### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade wheel setuptools
pip install -e ".[dev,packaging]"
```

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-dev \
	libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 \
	libxcb-keysyms1 libxcb-render-util0 libxcb-xinerama0 libxcb-xinput0 \
	libxcb-shape0 libmagic1 libmagic-dev -y

python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade wheel setuptools
pip install -e ".[dev,packaging]"
```

### macOS

```bash
brew update
brew install libmagic libomp

python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade wheel setuptools
pip install -e ".[dev,packaging]"
```

## 4. Verify installation

```bash
python main.py --help
pytest -q
```

Optional GUI check:

```bash
python main.py gui
```

## 5. Optional configuration

Copy config template:

### Windows

```powershell
Copy-Item .\config.yaml.example .\config.yaml
```

### Linux/macOS

```bash
cp ./config.yaml.example ./config.yaml
```

Notes:

- `config.yaml` is loaded from repository root.
- Set `bazaar_api_key` there for Intel fetch persistence.
- Environment variables override YAML values, for example:
	- Windows: `setx MSA_BAZAAR_API_KEY "<your-api-key>"`
	- Linux/macOS: `export MSA_BAZAAR_API_KEY="<your-api-key>"`

## 6. Common paths

- Runtime DB: `output/analyzer.db`
- Logs: `output/logs/`
- Downloaded ZIP samples: configurable in Intel tab
- Default sample folder: `malware_samples/`
