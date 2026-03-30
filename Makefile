PYTHON ?= .venv/Scripts/python.exe

.PHONY: test lint format run gui

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
