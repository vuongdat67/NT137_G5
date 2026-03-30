PYTHON ?= python

ifeq ($(OS),Windows_NT)
ifneq (,$(wildcard .venv/Scripts/python.exe))
PYTHON := .venv/Scripts/python.exe
endif
else
ifneq (,$(wildcard .venv/bin/python))
PYTHON := .venv/bin/python
endif
endif

.PHONY: test lint format run gui clean-build build-windows build-linux bundle-smoke

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy malware_analyzer

format:
	$(PYTHON) -m black .
	$(PYTHON) -m ruff check --fix .

run:
	$(PYTHON) main.py scan malware_samples --recursive --format both

gui:
	$(PYTHON) main.py gui

clean-build:
	-$(PYTHON) -c "import shutil; shutil.rmtree('build', ignore_errors=True); shutil.rmtree('dist', ignore_errors=True)"

build-windows:
ifeq ($(OS),Windows_NT)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install pyinstaller python-magic-bin
	$(PYTHON) -m PyInstaller --noconfirm --clean malware_analyzer.spec
else
	@echo "build-windows must run on Windows host"
	@exit 1
endif

build-linux:
ifneq ($(OS),Windows_NT)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install pyinstaller
	$(PYTHON) -m PyInstaller --noconfirm --clean malware_analyzer.spec
else
	@echo "build-linux must run on Linux host"
	@exit 1
endif

bundle-smoke:
	$(PYTHON) scripts/smoke_packaged_app.py
