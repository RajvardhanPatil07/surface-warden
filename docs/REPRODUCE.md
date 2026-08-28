# Reproduction guide

Everything below runs from a clean environment with **no host access, no
root, no API key and no network** after `pip install`. All evidence is
committed.

## Environment

| Requirement | Version used |
| --- | --- |
| OS | Any Linux, macOS or WSL2 (the scored evidence is committed, so no Linux host is needed) |
| Python | 3.11 or newer |
| Dependencies | `jsonschema>=4.21`, `PyYAML>=6.0` (see `requirements.txt`) |
| Node | Not required for the results below (dashboard only) |
| API key | Not required. Only the optional `--explain` narration uses one. |

## From a clean environment

```bash
git clone https://github.com/RajvardhanPatil07/surface-warden.git
cd surface-warden

python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## 1. The baseline

```bash
python warden.py baseline
```

Prints the static configuration checklist: number of findings, how much risk
weight it claims, and `usage measured: no`. Runs in under a second.

## 2. The advanced solution

```bash
python warden.py triage --budget 90000
```

The agent starts from the 60-second snapshot, decides whether to buy longer
observation windows, stops when the claim set stops changing, verifies every
generated artifact, and stops at a human approval gate. Runs in a few
seconds. Writes to `artifacts/runs/latest/`:

| File | What it is |
| --- | --- |
| `report.json` | Schema-valid deterministic report over the final evidence |
| `trajectory.jsonl` | Every agent step, tool response, retry and checkpoint |
| `verification.json` | Artifact checks, repairs applied, pass rate |
| `APPROVAL_REQUIRED.md` | The human checkpoint, with a revert for every step |
| `summary.json` | Headline numbers for the run |

To see the budget-limited behaviour, lower the budget:

```bash
python warden.py triage --budget 1000 --out artifacts/runs/cheap
```

## 3. The comparison

```bash
python warden.py evaluate
```

Runs all four arms and writes `artifacts/evaluation/comparison.json` and
`comparison.md`. This is the source of every number quoted in the README and
the changelog. Runs in a few seconds.

## 4. The tests

```bash
make verify
```

Runs the full suite plus the schema contract check. Equivalent to:

```bash
python -m unittest discover -s tests -v
python ksl.py scan --raw fixtures/raw-demo.json --no-explain -o /tmp/r.json
python ksl.py check /tmp/r.json
python scripts/check_contract.py /tmp/r.json
```

## Or just

```bash
make demo
```

Baseline, then agent triage, then the comparison, in order.

## Expected output

The assertions that must hold, all pinned by tests:

1. The **starting 60-second snapshot contains false orphan claims** - live
   surface wrongly reported as removable. (`test_starting_evidence_contains_false_claims`)
2. **False orphans fall monotonically** across baseline → single-shot →
   agent@1000s → agent@90000s. (`test_false_orphans_fall_as_evidence_is_bought`)
3. The **full-budget agent reaches zero false orphans** and matches the
   held-out ground truth exactly. (`test_agent_removes_every_false_claim`)
4. The **baseline would break live surface**. (`test_baseline_would_break_live_surface`)
5. **More correctness costs more evidence.** (`test_more_evidence_costs_more`)
6. The **report is a pure function of the final evidence set**, so the agent
   provably cannot influence a score. (`test_report_is_a_pure_function_of_final_evidence`)
7. Runs are **byte-identical** across invocations, trajectory included.
   (`test_run_is_reproducible_including_the_trajectory`)

## Cost and runtime

| Step | Wall clock | API cost |
| --- | --- | --- |
| `make demo` | Under 30 seconds | $0.00 |
| `make verify` | Under 60 seconds | $0.00 |
| Optional `--explain` narration | +30-60s | A few cents per run |
| Optional `--policy llm` | +5-20s | A few cents per run |

The headline result costs nothing to reproduce. The optional model paths are
not required for any number in the README.

## Scanning a real host

The original read-only collector is unchanged:

```bash
sudo python ksl.py scan --save-raw raw.json -o report.json   # read-only
python ksl.py check report.json
```

The agent replays a committed timeline rather than driving a live tracer; see
"What would break at scale" in `docs/AGENT_DESIGN.md`.

## Notes for reviewers

- The `ground_truth` block in `fixtures/timeline-demo.json` is the answer key.
  It is unreachable from every agent tool, and read only by the evaluation
  harness after a run finishes. There is a test asserting no tool output can
  leak it.
- `report.schema.json` is a frozen contract and was not modified for the
  competition. All new outputs live in separate paths.
- `make clean` removes generated run and evaluation directories.
