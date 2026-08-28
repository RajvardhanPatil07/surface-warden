"""The triage loop: acquire evidence, score deterministically, ask a human.

One run produces four things a reviewer can read independently:

- `report.json`     schema-valid deterministic report over the final evidence
- `trajectory.jsonl` every agent step, tool response, retry and checkpoint
- `verification.json` artifact checks, repairs and pass rate
- `APPROVAL_REQUIRED.md` the human checkpoint, with revert for every step

Nothing is ever applied to a host. The loop has no code path that writes
outside its own output directory.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent import WARDEN_AGENT_VERSION
from agent.policy import build_policy
from agent.tools import EvidenceTimeline, EvidenceTools
from agent.trajectory import Trajectory
from agent.verify import verify_plan

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TIMELINE = ROOT / "fixtures" / "timeline-demo.json"
MAX_STEPS = 16


def _approval_markdown(report: dict, verification: dict, summary: dict) -> str:
    """Render the human checkpoint document for one run."""
    lines = [
        "# Human approval required",
        "",
        "surface-warden generated the plan below and verified every artifact.",
        "**Nothing has been applied.** A qualified operator must review each step,",
        "apply it through normal change management, and keep the revert to hand.",
        "",
        f"- Evidence acquired: {', '.join(summary['windows_acquired'])}",
        f"- Observation window: {report['meta']['trace_seconds']}s "
        f"via {report['meta']['trace_backend']}",
        f"- Observation budget spent: {summary['evidence_cost_seconds']}s",
        f"- Artifacts passing verification: "
        f"{verification['artifacts_passed']}/{verification['artifacts_checked']}",
        f"- Reachable surface weight: {report['score']['reachable_surface_weight']} "
        f"-> {report['score']['projected_after_plan']['reachable_surface_weight']} "
        "if every step is applied",
        f"- Reachable CVEs: {report['score']['reachable_cve_count']} "
        f"-> {report['score']['projected_after_plan']['reachable_cve_count']}",
        "",
        "## Plan",
        "",
    ]
    for step in report["plan"]:
        lines += [
            f"### Step {step['step']}: {step['action']}",
            "",
            f"- Targets: {', '.join(step['targets'])}",
            f"- CVEs neutralised: {step['cves_killed']}",
            f"- Breakage risk: {step['breakage_risk']} - {step['breakage_note']}",
            f"- Requires reboot: {'yes' if step['requires_reboot'] else 'no'}",
            f"- Artifact: `{step['artifact']['path']}`",
            f"- Detect problems: `{step['detection']}`",
            f"- Revert: `{step['revert']}`",
            "",
        ]
    lines += [
        "## Evidence caveat",
        "",
        "`used` means observed during the observation window. Any workload quieter",
        "than that window can still look unused. Cross-check anything surprising",
        "against your own change calendar before applying it.",
        "",
    ]
    return "\n".join(lines)


def run_triage(
    timeline_path: str | Path = DEFAULT_TIMELINE,
    budget_seconds: int = 90_000,
    policy_name: str = "deterministic",
    out_dir: str | Path = ROOT / "artifacts" / "runs" / "latest",
    explain: bool = False,
    wall_clock: bool = False,
    max_steps: int = MAX_STEPS,
    quiet: bool = False,
) -> dict:
    """Run one triage session and write every artifact a judge needs."""
    from ksl import load_curated

    weights, cve_map = load_curated()
    timeline = EvidenceTimeline(timeline_path)
    tools = EvidenceTools(timeline, weights, cve_map, budget_seconds)
    policy = build_policy(policy_name)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    trajectory = Trajectory(
        out / "trajectory.jsonl",
        agent=f"surface-warden-triage/{WARDEN_AGENT_VERSION} ({policy.name})",
        instructions_ref="AGENTS.md#the-agent-boundary",
        wall_clock=wall_clock,
    )
    trajectory.record(
        phase="start",
        event="initial_evidence",
        observation=tools.describe_evidence(),
        detail=f"observation budget {budget_seconds}s",
    )

    steps = 0
    while not tools.finalized and steps < max_steps:
        steps += 1
        state = tools.state()
        decision = policy.next_action(state)
        if decision.get("fallback_reason"):
            trajectory.record(
                phase="decision",
                event="policy_fallback",
                retry_of=f"policy:{steps}",
                detail=decision["fallback_reason"],
                decision="overruled model choice, using documented stop rule",
            )
        result = tools.call(decision["action"], decision.get("arguments"))
        trajectory.record(
            phase="tool_call",
            step=steps,
            tool=decision["action"],
            tool_args=decision.get("arguments") or {},
            chosen_by=decision.get("chosen_by", policy.name),
            rationale=decision.get("rationale", ""),
            observation=result,
            claim_count=len(tools.claims),
        )
        if not result.get("ok") and decision["action"] == "request_trace_window":
            trajectory.record(
                phase="decision",
                event="acquisition_refused",
                retry_of=f"tool:{steps}",
                detail=result.get("reason", ""),
                decision="stop escalating and finalize with what the budget allowed",
            )
            tools.finalize(f"evidence acquisition refused: {result.get('reason', '')}")

    report = tools.report
    if explain:
        import explain.explain as ex

        report = ex.explain_report(report, artifacts=True)
        trajectory.record(
            phase="narration",
            event="explain_report",
            detail="narrative fields only; no scored field can change",
        )

    verification = verify_plan(report["plan"], trajectory=trajectory)

    summary = {
        "policy": policy.name,
        "steps": steps,
        "finalize_reason": tools.finalize_reason,
        "windows_acquired": tools.acquired,
        "final_window": tools.window_id,
        "evidence_cost_seconds": tools.spent_seconds,
        "budget_seconds": budget_seconds,
        "orphan_claims": list(tools.claims),
        "claims_crosschecked": list(tools.crosschecked),
        "score": report["score"],
        "verification": {
            key: verification[key]
            for key in (
                "artifacts_checked",
                "artifacts_passed",
                "validity_rate",
                "repairs_applied",
            )
        },
        "trajectory": trajectory.summary(),
        "applied_to_host": False,
    }

    from engine.report import validate_report

    validate_report(report)
    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (out / "verification.json").write_text(
        json.dumps(verification, indent=2, sort_keys=True) + "\n"
    )
    (out / "APPROVAL_REQUIRED.md").write_text(
        _approval_markdown(report, verification, summary)
    )

    trajectory.record(
        phase="human_checkpoint",
        event="approval_gate",
        status="pending_human_approval",
        detail=(
            "Plan and artifacts written for operator review. surface-warden has no "
            "code path that applies them."
        ),
        artifact=str(out / "APPROVAL_REQUIRED.md"),
    )
    trajectory.record(phase="end", event="run_complete", observation=summary)
    summary["trajectory"] = trajectory.summary()
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    if not quiet:
        print(f"triage complete ({policy.name} policy, {steps} steps)")
        print(f"  evidence acquired      : {' -> '.join(tools.acquired)}")
        print(f"  observation spend      : {tools.spent_seconds}s of {budget_seconds}s")
        print(f"  orphan claims          : {len(tools.claims)}")
        print(
            "  artifacts verified     : "
            f"{verification['artifacts_passed']}/{verification['artifacts_checked']}"
            f" ({verification['repairs_applied']} repaired)"
        )
        print(f"  stopped because        : {tools.finalize_reason}")
        print(f"  written to             : {out}")
        print("  applied to host        : no (human approval required)")
    return summary
