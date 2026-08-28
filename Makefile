# surface-warden - reproducible entry points.
#
# Everything below runs offline against committed evidence: no host access,
# no root, no API key, no network. That is deliberate - the headline result
# has to be reproducible on a reviewer's clean machine.

PY ?= python3
VENV ?= .venv
TIMELINE ?= fixtures/timeline-demo.json
BUDGET ?= 90000

.PHONY: help setup demo triage baseline evaluate verify test contract clean

help:
	@echo "surface-warden targets:"
	@echo "  make setup      create a venv and install requirements"
	@echo "  make demo       baseline, then agent triage, then the comparison"
	@echo "  make triage     run the evidence-acquisition agent"
	@echo "  make baseline   run the static configuration checklist"
	@echo "  make evaluate   score every arm and write artifacts/evaluation/"
	@echo "  make verify     run the full test suite and the schema contract check"
	@echo "  make test       run the test suite only"

setup:
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install -q -r requirements.txt
	@echo "activate with: . $(VENV)/bin/activate"

demo: baseline triage evaluate
	@echo
	@echo "Read artifacts/evaluation/comparison.md for the headline table"
	@echo "Read artifacts/runs/latest/APPROVAL_REQUIRED.md for the human checkpoint"
	@echo "Read artifacts/runs/latest/trajectory.jsonl for the agent trajectory"

triage:
	$(PY) warden.py triage --timeline $(TIMELINE) --budget $(BUDGET)

baseline:
	$(PY) warden.py baseline

evaluate:
	$(PY) warden.py evaluate --timeline $(TIMELINE)

verify: test contract

test:
	$(PY) -m unittest discover -s tests -v

contract:
	$(PY) ksl.py scan --raw fixtures/raw-demo.json --no-explain -o /tmp/ksl-report.json
	$(PY) ksl.py check /tmp/ksl-report.json
	$(PY) scripts/check_contract.py /tmp/ksl-report.json

clean:
	rm -rf artifacts/runs artifacts/evaluation /tmp/ksl-report.json
