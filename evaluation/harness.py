"""Baseline vs advanced, scored against a held-out answer key.

Four arms over identical inputs:

1. `baseline_static_checklist`  - static configuration checklist, the method
   used by mainstream kernel hardening checkers. No usage evidence.
2. `advanced_single_shot`       - the deterministic engine (reachability
   gating, workload attribution, breakage-costed set cover) on the one
   snapshot the operator handed over.
3. `advanced_agent_budget_1000` - the same engine, with the agent allowed to
   spend up to 1000 observation-seconds acquiring more evidence.
4. `advanced_agent_budget_90000` - the same, with a full-day budget.

The two agent arms exist so the cost/correctness trade-off is visible as a
curve rather than asserted as a win. Buying more observation time is not
free, and the harness reports exactly what it bought.

The metric that matters:

    safe risk removed per unit of expected breakage

where "safe" means the surface really was unused, established from the
timeline's held-out ground truth. An arm that recommends removing surface a
live workload depends on is charged for it, because in production that is an
outage rather than a hardening win.

The answer key is read here and nowhere else. No agent tool can reach it.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent.loop import run_triage
from agent.tools import EvidenceTimeline
from agent.verify import verify_plan
from baseline.checklist import build_checklist
from engine.reachability import MODULE_MEMBERS
from engine.report import build_report
from engine.setcover import SECCOMP_DENY, SYSCTL_SETTING

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TIMELINE = ROOT / "fixtures" / "timeline-demo.json"
OUT_DIR = ROOT / "artifacts" / "evaluation"

# Expected breakage cost of one change, in the same units the planner uses.
COST_SAFE = 1  # surface really was unused
COST_IN_USE = 4  # a live workload depends on it
COST_REBOOT = 12  # requires a kernel rebuild or reboot


def step_touches_element(step: dict, element: dict) -> bool:
    """Whether a plan step acts on a given surface element.

    Plan targets are concrete artifact targets (module names, `key=value`
    sysctl settings, syscall names), not element ids, so the mapping back to
    elements goes through the element's own name, its member modules, and the
    settings named in its curated mitigations.
    """
    targets = set(step["targets"])
    names = set(MODULE_MEMBERS.get(element["id"], (element["name"],)))
    if names & targets:
        return True
    for mitigation in element["mitigations"]:
        sysctl = SYSCTL_SETTING.search(str(mitigation))
        if sysctl and f"{sysctl.group(1)}={sysctl.group(2)}" in targets:
            return True
        seccomp = SECCOMP_DENY.search(str(mitigation))
        if seccomp and any(
            name.strip() in targets for name in seccomp.group(1).split(",")
        ):
            return True
    return False


def _score_changes(changes: list[dict], used: set[str], orphaned: set[str]) -> dict:
    """Score a list of {elements, weight, reboot} change records."""
    cost = 0
    incidents = 0
    safe_weight = 0.0
    unsafe_elements: set[str] = set()
    safe_elements: set[str] = set()

    for change in changes:
        touched = set(change["elements"])
        hits_used = touched & used
        if change["reboot"]:
            cost += COST_REBOOT
        elif hits_used:
            cost += COST_IN_USE
        else:
            cost += COST_SAFE
        if hits_used:
            incidents += 1
            unsafe_elements |= hits_used
        safe_elements |= touched & orphaned

    safe_weight = round(
        sum(change["weights"].get(eid, 0.0) for change in changes for eid in change["elements"] if eid in orphaned),
        2,
    )
    return {
        "changes": len(changes),
        "expected_breakage_cost": cost,
        "breakage_incidents": incidents,
        "elements_broken": sorted(unsafe_elements),
        "safe_risk_removed": safe_weight,
        "safe_elements_removed": sorted(safe_elements),
        "safe_risk_per_breakage_cost": round(safe_weight / cost, 3) if cost else 0.0,
    }


def _claim_metrics(claims: list[str], used: set[str], orphaned: set[str]) -> dict:
    """Correctness of the orphan claim set against the answer key."""
    claimed = set(claims)
    false_orphans = sorted(claimed & used)
    missed = sorted(orphaned - claimed)
    return {
        "claims": len(claimed),
        "false_orphans": len(false_orphans),
        "false_orphan_ids": false_orphans,
        "missed_orphans": len(missed),
        "missed_orphan_ids": missed,
        "precision": round(len(claimed & orphaned) / len(claimed), 3) if claimed else 0.0,
        "recall": round(len(claimed & orphaned) / len(orphaned), 3) if orphaned else 0.0,
    }


def _advanced_changes(report: dict) -> list[dict]:
    """Turn plan steps into change records with the elements they touch."""
    elements = report["surface_elements"]
    weights = {e["id"]: e["weight"] for e in elements}
    changes = []
    for step in report["plan"]:
        touched = sorted(
            e["id"] for e in elements if step_touches_element(step, e)
        )
        changes.append(
            {
                "action": step["action"],
                "elements": touched,
                "weights": weights,
                "reboot": bool(step["requires_reboot"]),
            }
        )
    return changes


def _baseline_changes(checklist: dict) -> list[dict]:
    """One change record per static finding."""
    weights = {f["id"]: f["weight"] for f in checklist["findings"]}
    return [
        {
            "action": finding["recommendation"],
            "elements": [finding["id"]],
            "weights": weights,
            "reboot": finding["kind"] == "kconfig",
        }
        for finding in checklist["findings"]
    ]


def run_evaluation(
    timeline_path: str | Path = DEFAULT_TIMELINE,
    out_dir: str | Path = OUT_DIR,
) -> dict:
    """Run every arm and write the comparison artifacts."""
    from ksl import load_curated

    weights, cve_map = load_curated()
    timeline = EvidenceTimeline(timeline_path)
    truth = timeline.ground_truth
    used = set(truth.get("used_elements", []))
    orphaned = set(truth.get("orphaned_elements", []))

    arms: dict[str, dict] = {}

    # 1. baseline -------------------------------------------------------
    start_raw = timeline.snapshot(timeline.start_window)
    checklist = build_checklist(start_raw, weights, cve_map)
    arms["baseline_static_checklist"] = {
        "description": "static configuration checklist, no usage evidence",
        "observation_seconds": 0,
        "evidence_cost_seconds": 0,
        "artifact_validity_rate": None,
        **_claim_metrics(checklist["claims_orphaned"], used, orphaned),
        **_score_changes(_baseline_changes(checklist), used, orphaned),
    }

    # 2. advanced, single shot -----------------------------------------
    single = build_report(start_raw, weights, cve_map)
    single_verification = verify_plan(single["plan"])
    arms["advanced_single_shot"] = {
        "description": "deterministic engine on the handed-over snapshot",
        "observation_seconds": single["meta"]["trace_seconds"],
        "evidence_cost_seconds": 0,
        "artifact_validity_rate": single_verification["validity_rate"],
        **_claim_metrics(single["orphaned"]["elements"], used, orphaned),
        **_score_changes(_advanced_changes(single), used, orphaned),
    }

    # 3+4. advanced, agent-acquired evidence ---------------------------
    for budget in (1000, 90_000):
        name = f"advanced_agent_budget_{budget}"
        summary = run_triage(
            timeline_path=timeline_path,
            budget_seconds=budget,
            policy_name="deterministic",
            out_dir=ROOT / "artifacts" / "runs" / name,
            quiet=True,
        )
        report = json.loads(
            (ROOT / "artifacts" / "runs" / name / "report.json").read_text()
        )
        arms[name] = {
            "description": f"agent acquires evidence within {budget}s of observation",
            "observation_seconds": report["meta"]["trace_seconds"],
            "evidence_cost_seconds": summary["evidence_cost_seconds"],
            "artifact_validity_rate": summary["verification"]["validity_rate"],
            "windows_acquired": summary["windows_acquired"],
            "stopped_because": summary["finalize_reason"],
            **_claim_metrics(report["orphaned"]["elements"], used, orphaned),
            **_score_changes(_advanced_changes(report), used, orphaned),
        }

    result = {
        "timeline": str(Path(timeline_path).relative_to(ROOT))
        if Path(timeline_path).is_absolute()
        else str(timeline_path),
        "ground_truth_note": truth.get("note", ""),
        "cost_model": {
            "safe_change": COST_SAFE,
            "change_touching_live_surface": COST_IN_USE,
            "change_requiring_reboot": COST_REBOOT,
            "note": (
                "Expected breakage cost is charged from the answer key, so every "
                "arm is billed for the outages its recommendations would cause."
            ),
        },
        "arms": arms,
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "comparison.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (out / "comparison.md").write_text(render_markdown(result))
    return result


COLUMNS = (
    ("claims", "Claims"),
    ("false_orphans", "False orphans"),
    ("missed_orphans", "Missed orphans"),
    ("precision", "Precision"),
    ("breakage_incidents", "Breakage incidents"),
    ("safe_risk_removed", "Safe risk removed"),
    ("expected_breakage_cost", "Breakage cost"),
    ("safe_risk_per_breakage_cost", "Risk/cost"),
    ("evidence_cost_seconds", "Evidence cost (s)"),
)


def render_markdown(result: dict) -> str:
    """Render the comparison as a Markdown table for the README and changelog."""
    arms = result["arms"]
    names = list(arms)
    lines = [
        "# Baseline vs advanced",
        "",
        "Generated by `make evaluate`. Every arm sees the same host, the same",
        "curated risk table and the same CVE map. Ground truth is held out from",
        "every agent tool and read only by the harness.",
        "",
        "| Metric | " + " | ".join(names) + " |",
        "| --- | " + " | ".join("---" for _ in names) + " |",
    ]
    for key, label in COLUMNS:
        row = [str(arms[name].get(key, "-")) for name in names]
        lines.append(f"| {label} | " + " | ".join(row) + " |")
    lines += [
        "",
        "**Risk/cost** is safe risk weight removed per unit of expected breakage",
        "cost - the single number that captures 'hardened the host without causing",
        "an outage'.",
        "",
        f"Ground truth: {result['ground_truth_note']}",
        "",
    ]
    for name in names:
        arm = arms[name]
        lines.append(f"### {name}")
        lines.append("")
        lines.append(f"{arm['description']}.")
        if arm.get("false_orphan_ids"):
            lines.append(
                f"Falsely claimed unused: `{'`, `'.join(arm['false_orphan_ids'])}`."
            )
        if arm.get("elements_broken"):
            lines.append(
                f"Would have broken: `{'`, `'.join(arm['elements_broken'])}`."
            )
        if arm.get("stopped_because"):
            lines.append(f"Stopped because: {arm['stopped_because']}.")
        lines.append("")
    return "\n".join(lines)


def print_table(result: dict) -> None:
    """Print a compact terminal table."""
    arms = result["arms"]
    width = max(len(label) for _, label in COLUMNS) + 2
    names = list(arms)
    print("\nbaseline vs advanced\n")
    print(" " * width + "".join(f"{name[:26]:>28}" for name in names))
    for key, label in COLUMNS:
        row = "".join(f"{str(arms[name].get(key, '-')):>28}" for name in names)
        print(f"{label:<{width}}" + row)
    print()


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the evaluation harness."""
    import argparse

    parser = argparse.ArgumentParser(description="Run the baseline/advanced comparison")
    parser.add_argument("--timeline", default=str(DEFAULT_TIMELINE))
    parser.add_argument("--out", default=str(OUT_DIR))
    args = parser.parse_args(argv)

    result = run_evaluation(args.timeline, args.out)
    print_table(result)
    print(f"wrote {Path(args.out) / 'comparison.json'}")
    print(f"wrote {Path(args.out) / 'comparison.md'}")
    return 0
