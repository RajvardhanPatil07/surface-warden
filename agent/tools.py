"""Read-only evidence tools available to the triage agent.

The frontier problem this addresses: a kernel surface report is only as
good as its observation window. `used` means "observed during the trace
window", so a 60-second daytime trace makes a quiet nightly job look like
free hardening. The deterministic engine cannot resolve that on its own -
it can only score the evidence it was handed. Deciding *which additional
evidence is worth buying, and when the answer has stopped changing*, is a
judgment call with a real cost attached, and it is checkable.

Every tool here is a pure function of a replayable evidence timeline, so a
run needs no host access, no root, and no API key.

The timeline's `ground_truth` block is deliberately NOT reachable through
any tool. Only `scripts/evaluate.py` reads it, after the run has finished.
The agent is scored against evidence it was never allowed to see.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from engine.report import build_report

ROOT = Path(__file__).resolve().parent.parent

# Below this, an absent syscall is not evidence of an unused syscall: too
# short to have observed a periodic workload even once.
MIN_CONFIDENT_TRACE_SECONDS = 900


class EvidenceTimeline:
    """A replayable series of read-only snapshots at increasing trace windows."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        data = json.loads(self.path.read_text())
        self.base: dict = json.loads((ROOT / data["base_snapshot"]).read_text())
        self.windows: list[dict] = sorted(
            data["windows"], key=lambda w: w["trace_seconds"]
        )
        self.by_id: dict[str, dict] = {w["id"]: w for w in self.windows}
        self.start_window: str = data.get("start_window", self.windows[0]["id"])
        self.ground_truth: dict = data.get("ground_truth", {})

    def snapshot(self, window_id: str) -> dict:
        """Materialise the raw snapshot recorded for one observation window."""
        window = self.by_id[window_id]
        raw = copy.deepcopy(self.base)
        raw["meta"]["trace_backend"] = window["trace_backend"]
        raw["meta"]["trace_seconds"] = window["trace_seconds"]
        raw["traced_syscalls"] = copy.deepcopy(window.get("traced_syscalls", {}))
        known = {w["id"] for w in raw["workloads"]}
        for extra in window.get("extra_workloads", []):
            if extra["id"] not in known:
                raw["workloads"].append(copy.deepcopy(extra))
        raw["workloads"].sort(key=lambda w: w["id"])
        return raw

    def longer_than(self, seconds: int) -> dict | None:
        """Smallest recorded window strictly longer than `seconds`."""
        for window in self.windows:
            if window["trace_seconds"] > seconds:
                return window
        return None

    def at_least(self, seconds: int) -> dict | None:
        """Smallest recorded window of at least `seconds`."""
        for window in self.windows:
            if window["trace_seconds"] >= seconds:
                return window
        return None


# Tool name -> one-line contract, also used to build the LLM policy prompt.
TOOL_CONTRACTS: dict[str, str] = {
    "describe_evidence": "Report the current observation window, budget and available windows.",
    "list_orphan_claims": "List surface elements currently claimed orphaned (reachable but unused).",
    "crosscheck_claim": "Show the raw evidence behind one claim. Args: element_id.",
    "request_trace_window": "Acquire a longer read-only trace window. Args: seconds. Costs budget.",
    "score_current": "Recompute the deterministic score for the current evidence.",
    "finalize": "Stop acquiring evidence and hand the report to a human. Args: reason.",
}


class EvidenceTools:
    """The tool surface a policy is allowed to call, with budget accounting."""

    def __init__(
        self,
        timeline: EvidenceTimeline,
        weights: dict,
        cve_map: dict,
        budget_seconds: int,
    ) -> None:
        self.timeline = timeline
        self.weights = weights
        self.cve_map = cve_map
        self.budget_seconds = budget_seconds
        self.spent_seconds = 0
        self.window_id = timeline.start_window
        self.finalized = False
        self.finalize_reason = ""
        self.crosschecked: list[str] = []
        self.acquired: list[str] = [timeline.start_window]
        self.previous_claims: list[str] | None = None
        self.claims_changed: bool | None = None
        self._recompute()

    # ------------------------------------------------------------------
    # internal state

    def _recompute(self) -> None:
        """Re-run the deterministic engine over the current evidence."""
        self.raw = self.timeline.snapshot(self.window_id)
        self.report = build_report(self.raw, self.weights, self.cve_map)
        self.claims = list(self.report["orphaned"]["elements"])

    @property
    def budget_remaining(self) -> int:
        """Observation seconds still affordable."""
        return max(self.budget_seconds - self.spent_seconds, 0)

    def state(self) -> dict:
        """Compact state handed to the policy on every step."""
        meta = self.report["meta"]
        affordable = [
            {
                "id": window["id"],
                "trace_seconds": window["trace_seconds"],
                "cost_seconds": window["cost_seconds"],
            }
            for window in self.timeline.windows
            if window["trace_seconds"] > meta["trace_seconds"]
            and window["cost_seconds"] <= self.budget_remaining
        ]
        return {
            "window_id": self.window_id,
            "trace_backend": meta["trace_backend"],
            "trace_seconds": meta["trace_seconds"],
            "min_confident_trace_seconds": MIN_CONFIDENT_TRACE_SECONDS,
            "orphan_claims": list(self.claims),
            "previous_claims": self.previous_claims,
            "claims_changed": self.claims_changed,
            "crosschecked": list(self.crosschecked),
            "budget_remaining": self.budget_remaining,
            "affordable_windows": affordable,
            "score": {
                "reachable_surface_weight": self.report["score"]["reachable_surface_weight"],
                "reachable_cve_count": self.report["score"]["reachable_cve_count"],
            },
        }

    # ------------------------------------------------------------------
    # tools

    def describe_evidence(self) -> dict:
        """Current window, spend, and what else could be acquired."""
        meta = self.report["meta"]
        return {
            "ok": True,
            "window_id": self.window_id,
            "trace_backend": meta["trace_backend"],
            "trace_seconds": meta["trace_seconds"],
            "ran_as_root": meta["ran_as_root"],
            "skipped_sources": [s["source"] for s in meta["skipped"]],
            "workloads_observed": len(self.report["workloads"]),
            "budget_spent_seconds": self.spent_seconds,
            "budget_remaining_seconds": self.budget_remaining,
            "windows_available": [
                {
                    "id": w["id"],
                    "trace_seconds": w["trace_seconds"],
                    "cost_seconds": w["cost_seconds"],
                }
                for w in self.timeline.windows
            ],
        }

    def list_orphan_claims(self) -> dict:
        """Elements currently claimed orphaned, with weight and kind."""
        by_id = {e["id"]: e for e in self.report["surface_elements"]}
        return {
            "ok": True,
            "count": len(self.claims),
            "claims": [
                {
                    "id": eid,
                    "kind": by_id[eid]["kind"],
                    "name": by_id[eid]["name"],
                    "weight": by_id[eid]["weight"],
                }
                for eid in self.claims
            ],
            "total_weight": self.report["orphaned"]["total_weight"],
            "cves_neutralizable": self.report["orphaned"]["cves_neutralizable"],
        }

    def crosscheck_claim(self, element_id: str) -> dict:
        """Raw evidence behind one claim, so a claim is never taken on trust."""
        by_id = {e["id"]: e for e in self.report["surface_elements"]}
        element = by_id.get(element_id)
        if element is None:
            return {"ok": False, "reason": f"unknown element {element_id}"}
        if element_id not in self.crosschecked:
            self.crosschecked.append(element_id)
        touchers = sorted(
            w["id"] for w in self.report["workloads"] if element_id in w["touches"]
        )
        loaded = {m["name"]: m["instances"] for m in self.raw["modules_loaded"]}
        return {
            "ok": True,
            "id": element_id,
            "kind": element["kind"],
            "present": element["present"],
            "reachable_unpriv": element["reachable_unpriv"],
            "used": element["used"],
            "gate_reason": element["gate_reason"],
            "touched_by": touchers,
            "module_instances": loaded.get(element["name"]),
            "observation_window_seconds": self.report["meta"]["trace_seconds"],
            "caveat": (
                "'used' is scoped to the observation window; absence of usage in a "
                "short window is not evidence of absence."
            ),
        }

    def request_trace_window(self, seconds: int) -> dict:
        """Acquire a longer read-only observation window, charged to the budget."""
        try:
            wanted = int(seconds)
        except (TypeError, ValueError):
            return {"ok": False, "reason": f"seconds must be an integer, got {seconds!r}"}
        window = self.timeline.at_least(wanted)
        if window is None:
            return {
                "ok": False,
                "reason": f"no recorded window of at least {wanted}s",
                "longest_available": self.timeline.windows[-1]["trace_seconds"],
            }
        if window["trace_seconds"] <= self.report["meta"]["trace_seconds"]:
            return {"ok": False, "reason": "window is not longer than current evidence"}
        if window["cost_seconds"] > self.budget_remaining:
            return {
                "ok": False,
                "reason": "insufficient budget",
                "cost_seconds": window["cost_seconds"],
                "budget_remaining_seconds": self.budget_remaining,
            }

        before = list(self.claims)
        self.spent_seconds += window["cost_seconds"]
        self.window_id = window["id"]
        self.acquired.append(window["id"])
        self._recompute()
        newly_used = sorted(set(before) - set(self.claims))
        newly_claimed = sorted(set(self.claims) - set(before))
        self.previous_claims = before
        self.claims_changed = bool(newly_used or newly_claimed)
        return {
            "ok": True,
            "window_id": window["id"],
            "trace_backend": window["trace_backend"],
            "trace_seconds": window["trace_seconds"],
            "cost_seconds": window["cost_seconds"],
            "note": window.get("note", ""),
            "claims_withdrawn": newly_used,
            "claims_added": newly_claimed,
            "claims_changed": self.claims_changed,
            "budget_remaining_seconds": self.budget_remaining,
        }

    def score_current(self) -> dict:
        """Deterministic headline score for the current evidence."""
        score = self.report["score"]
        return {
            "ok": True,
            "reachable_surface_weight": score["reachable_surface_weight"],
            "reachable_cve_count": score["reachable_cve_count"],
            "orphan_ratio": score["orphan_ratio"],
            "projected_after_plan": score["projected_after_plan"],
            "plan_steps": len(self.report["plan"]),
        }

    def finalize(self, reason: str = "") -> dict:
        """Stop acquiring evidence; the report goes to a human for approval."""
        self.finalized = True
        self.finalize_reason = str(reason)
        return {"ok": True, "finalized": True, "reason": self.finalize_reason}

    def call(self, action: str, arguments: dict | None = None) -> dict:
        """Dispatch a tool call by name, rejecting anything not on the menu."""
        arguments = dict(arguments or {})
        if action not in TOOL_CONTRACTS:
            return {"ok": False, "reason": f"tool {action!r} is not available"}
        method = getattr(self, action)
        try:
            return method(**arguments)
        except TypeError as exc:
            return {"ok": False, "reason": f"bad arguments for {action}: {exc}"}
