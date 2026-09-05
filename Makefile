# =============================================================================
# AEGIS - Makefile
#
# This mirrors aegis.ps1 for Linux/macOS and for the GitHub Actions runners.
# The PowerShell script is the day-to-day driver on the Windows dev machine;
# this file is what CI executes. Keeping both in sync is deliberate: a project
# that only builds on its author's laptop is not a portfolio piece.
# =============================================================================

SHELL := /bin/bash
VENV  ?= .venv
PY    := $(VENV)/bin/python
COMPOSE := docker compose --env-file .env -f infra/docker-compose.yml

.DEFAULT_GOAL := help
.PHONY: help setup up down restart ps logs stats nuke doctor lint format types test check ci

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# --- Environment -------------------------------------------------------------
setup:  ## Create the venv and install all dependencies
	python3 -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"
	@test -f .env || cp .env.example .env

# --- Infrastructure ----------------------------------------------------------
up:  ## Start redpanda, minio, postgres, console
	$(COMPOSE) up -d
down:  ## Stop containers, keep data
	$(COMPOSE) down
restart:  ## Restart every container
	$(COMPOSE) restart
ps:  ## Container status
	$(COMPOSE) ps
logs:  ## Follow logs
	$(COMPOSE) logs -f --tail=100
stats:  ## Live memory and CPU
	docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.CPUPerc}}"
nuke:  ## Destroy every volume (DESTRUCTIVE)
	$(COMPOSE) down -v

doctor:  ## Diagnose the environment
	$(PY) scripts/doctor.py

# --- Quality gates -----------------------------------------------------------
lint:  ## Ruff lint
	$(PY) -m ruff check src tests
format:  ## Ruff format + autofix
	$(PY) -m ruff format src tests
	$(PY) -m ruff check --fix src tests
types:  ## mypy
	$(PY) -m mypy src
test:  ## pytest
	$(PY) -m pytest tests -v
check: lint types test  ## All quality gates

ci: check  ## What GitHub Actions runs
