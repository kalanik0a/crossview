.PHONY: help install update tui scan clean test lint fmt screenshots \
        dev-verify-urls dev-inspect dev-schema dev-sample dev-validate dev-stats dev-sql

VENV    := .venv
PYTHON  := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
CROSSVIEW := $(VENV)/bin/crossview

help:
	@echo "Crossview Makefile targets:"
	@echo "  install            Create venv and install crossview + dev deps"
	@echo "  update             Re-download all MITRE data and rebuild DB"
	@echo "  tui                Launch the Textual TUI"
	@echo "  scan PATH=<dir>    Scan code at PATH, write report to PATH/CROSSVIEW-REPORT.md"
	@echo "  test               Run pytest"
	@echo "  lint               Run ruff"
	@echo "  fmt                Format with ruff"
	@echo "  screenshots        Regenerate docs/assets screenshots (cli/tui/web)"
	@echo "  clean              Remove venv, __pycache__, and built artifacts"
	@echo ""
	@echo "Internal data tooling (dev-*):"
	@echo "  dev-verify-urls    HEAD-check every MITRE source URL"
	@echo "  dev-inspect FILE=  Show structure of a downloaded JSON file"
	@echo "  dev-schema FILE=   Infer schema from a downloaded JSON file"
	@echo "  dev-sample FILE=   Sample N entities from a downloaded file"
	@echo "  dev-validate       Run integrity checks across the SQLite DB"
	@echo "  dev-stats          Print DB row counts per table"
	@echo "  dev-sql QUERY=     Run a raw SQL query against the DB"

install:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

update:
	$(CROSSVIEW) update

tui:
	$(CROSSVIEW) tui

scan:
	@if [ -z "$(PATH_)" ]; then echo "Usage: make scan PATH_=<dir>"; exit 1; fi
	$(CROSSVIEW) scan $(PATH_)

test:
	$(VENV)/bin/pytest tests/ -v

lint:
	$(VENV)/bin/ruff check crossview/

fmt:
	$(VENV)/bin/ruff format crossview/

# Regenerate documentation screenshots into docs/assets/.
# Surfaces: cli (Rich→SVG), tui (Textual→SVG), web (GraphiQL via Playwright).
# Pass SURFACES to limit, e.g. `make screenshots SURFACES=cli`.
screenshots:
	$(PYTHON) scripts/gen_screenshots.py $(SURFACES)

clean:
	rm -rf $(VENV) build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +

dev-verify-urls:
	$(CROSSVIEW) dev verify-urls

dev-inspect:
	@if [ -z "$(FILE)" ]; then echo "Usage: make dev-inspect FILE=<path>"; exit 1; fi
	$(CROSSVIEW) dev inspect $(FILE)

dev-schema:
	@if [ -z "$(FILE)" ]; then echo "Usage: make dev-schema FILE=<path>"; exit 1; fi
	$(CROSSVIEW) dev schema $(FILE)

dev-sample:
	@if [ -z "$(FILE)" ]; then echo "Usage: make dev-sample FILE=<path>"; exit 1; fi
	$(CROSSVIEW) dev sample $(FILE)

dev-validate:
	$(CROSSVIEW) dev validate

dev-stats:
	$(CROSSVIEW) dev stats

dev-sql:
	@if [ -z "$(QUERY)" ]; then echo "Usage: make dev-sql QUERY='SELECT ...'"; exit 1; fi
	$(CROSSVIEW) dev sql "$(QUERY)"
