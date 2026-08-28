# Instructions for coding agents

Read this before writing any code in this repository.

## Non-negotiable rules

1. **`report.schema.json` is a frozen contract.** Read it first. Every artifact you produce must validate against it. If you believe it needs to change, say so and stop - do not change it unilaterally, and never change it without updating `fixtures/demo.json` in the same commit.

2. **The collector is strictly read-only.** Never write outside the explicit output path. Never load or unload a kernel module. Never modify a sysctl. Hardening artifacts are *generated for human review*, never applied.

3. **Degrade, never crash.** Every read of `/proc`, `/sys`, or `/boot` must tolerate `PermissionError` and `FileNotFoundError`, record the reason in `meta.skipped`, and continue. The tool must produce a useful partial report when run as an unprivileged user.

4. **The engine must be deterministic.** Sort every collection before emitting. No dependence on dict ordering, no randomness, no wall-clock values in scored fields. Two runs over the same `raw.json` must produce byte-identical `report.json`. There is a test for this.

5. **The LLM never decides anything.** It writes `ledger[].explanation`, `plan[].breakage_note`, `plan[].detection`, `plan[].revert`, and may render `plan[].artifact.content`. It must never influence a weight, a gate, a score, or an ordering. `--explain-only=false` must yield identical numeric output. There is a test for this.

6. **Do not invent risk weights or CVE mappings.** Those live in `data/weights.yaml` and `data/cve-map.json` and are curated by a human. Read them; never generate them.

7. **No secrets in the repo.** API configuration comes from `KSL_API_BASE`, `KSL_API_KEY`, `KSL_MODEL` environment variables only.

## The agent boundary

Rule 5 is about **scoring**, and it holds without exception. `agent/` adds a
policy that makes exactly one class of decision, and this section states the
boundary precisely so a reviewer can check it rather than take it on trust.

An agent policy **may** decide:

- which read-only observation window to acquire next, and when to stop;
- which orphan claims to cross-check against raw evidence;
- when the evidence has converged enough to hand to a human.

An agent policy **may never**:

- change a weight, a gate predicate, a score, a CVE mapping, or a plan ordering;
- add, drop, or reorder a plan step;
- apply an artifact, or write anywhere outside its own run directory.

The invariant, which is the reason this is safe:

> **The report is a pure function of the final evidence set.**

Two runs that end on the same evidence produce identical reports, whichever
policy chose that evidence, and whether or not a model was involved. There is
a test for this (`tests/test_agent_evidence.py`). The blast radius of a bad
agent decision is bounded to "bought too much or too little observation
time" - a cost error, never a correctness error.

When adding a tool to `agent/tools.py`, it must be read-only, a pure function
of the evidence timeline, and must not expose the timeline's `ground_truth`
block. That block is the held-out answer key for evaluation only.

## Definitions you must implement exactly

- `present` - compiled in (`=y`), currently loaded, or loadable via module autoload (`modules.dep`).
- `reachable_unpriv` - `present` AND not blocked by its sysctl gate AND not blocked by lockdown/LSM AND (for device nodes) the mode grants non-root access.
- `used` - invoked or held open by at least one live workload during the observation window.
- `observation window` - the wall-clock duration the tracer ran. `used` is only
  meaningful inside it: a workload quieter than the window looks unused. Treat
  window length as evidence to be acquired, not as a fixed input.
- `sole_owner_elements` - elements touched by exactly one workload.
- `surface_debt(w)` - `sum(weight of sole-owner elements) + sum(weight / n_touchers for shared elements)`.
- `marginal_contribution(w)` - `total_reachable_weight - total_reachable_weight_without_w`.
- `orphaned` - `present AND reachable_unpriv AND NOT used` by any workload, restricted
  to *removable* kinds (`syscall`, `module`, `devnode`, `namespace`, `capability`).
  Exclude `sysctl`, `kconfig`, and `lsm`: a misconfigured flag is a missing hardening
  setting, not orphaned surface, and `used` is not meaningful for it. Those still
  appear as plan candidates, just never in the orphaned set.
- `false orphan` - an element claimed `orphaned` that a live workload actually
  uses. This is the failure mode the evaluation harness measures, because it is
  the one that causes outages.

## Style

Python 3.11, type hints and docstrings on every public function, stdlib only in `collector/` (`jsonschema` and `PyYAML` are permitted in `engine/`). After writing code, run it and fix your own errors before reporting back.

New competition code lives in `agent/`, `baseline/`, and `evaluation/`; it must
not modify `engine/`, `collector/`, `ksl.py`, or `report.schema.json`.
