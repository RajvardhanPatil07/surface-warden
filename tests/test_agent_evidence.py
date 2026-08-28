"""The agent decides what evidence to buy - and nothing else.

These tests pin the invariant that makes the design safe to ship: the
report is a pure function of the final evidence set. Whichever policy
selected that evidence, and whether or not a model was involved, the
numbers are identical.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.loop import run_triage
from agent.tools import EvidenceTimeline, EvidenceTools, TOOL_CONTRACTS
from engine.report import build_report
from ksl import load_curated

TIMELINE = ROOT / "fixtures" / "timeline-demo.json"


class TestEvidenceTimeline(unittest.TestCase):
    """The timeline must be replayable and internally consistent."""

    def setUp(self) -> None:
        self.timeline = EvidenceTimeline(TIMELINE)

    def test_windows_are_ordered_and_priced(self) -> None:
        seconds = [w["trace_seconds"] for w in self.timeline.windows]
        self.assertEqual(seconds, sorted(seconds))
        for window in self.timeline.windows:
            self.assertGreaterEqual(window["cost_seconds"], 0)

    def test_snapshots_are_deterministic(self) -> None:
        for window in self.timeline.windows:
            first = json.dumps(self.timeline.snapshot(window["id"]), sort_keys=True)
            second = json.dumps(self.timeline.snapshot(window["id"]), sort_keys=True)
            self.assertEqual(first, second, window["id"])

    def test_longer_windows_reveal_more_usage(self) -> None:
        """Each escalation may only add observed usage, never retract it."""
        seen: set[str] = set()
        for window in self.timeline.windows:
            raw = self.timeline.snapshot(window["id"])
            traced = {
                name for names in raw["traced_syscalls"].values() for name in names
            }
            self.assertTrue(
                seen.issubset(traced),
                f"{window['id']} lost usage evidence seen in a shorter window",
            )
            seen = traced

    def test_ground_truth_is_disjoint(self) -> None:
        truth = self.timeline.ground_truth
        self.assertFalse(
            set(truth["used_elements"]) & set(truth["orphaned_elements"]),
            "an element cannot be both used and orphaned",
        )


class TestToolBoundary(unittest.TestCase):
    """No tool may leak the answer key."""

    def setUp(self) -> None:
        weights, cve_map = load_curated()
        self.timeline = EvidenceTimeline(TIMELINE)
        self.tools = EvidenceTools(self.timeline, weights, cve_map, budget_seconds=90_000)

    def test_ground_truth_is_not_reachable_from_any_tool(self) -> None:
        outputs = [self.tools.describe_evidence(), self.tools.list_orphan_claims()]
        outputs.append(self.tools.score_current())
        for claim in self.tools.claims:
            outputs.append(self.tools.crosscheck_claim(claim))
        outputs.append(self.tools.request_trace_window(86_400))
        blob = json.dumps(outputs)
        self.assertNotIn("ground_truth", blob)
        self.assertNotIn(self.timeline.ground_truth["note"], blob)
        self.assertNotIn("answer", blob.lower().replace("answered", ""))

    def test_unknown_tools_are_refused(self) -> None:
        result = self.tools.call("apply_hardening", {})
        self.assertFalse(result["ok"])
        self.assertNotIn("apply_hardening", TOOL_CONTRACTS)

    def test_bad_arguments_are_refused_not_raised(self) -> None:
        self.assertFalse(self.tools.call("crosscheck_claim", {"nope": 1})["ok"])
        self.assertFalse(self.tools.request_trace_window("soon")["ok"])

    def test_budget_is_enforced(self) -> None:
        weights, cve_map = load_curated()
        poor = EvidenceTools(self.timeline, weights, cve_map, budget_seconds=100)
        result = poor.request_trace_window(900)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "insufficient budget")
        self.assertEqual(poor.spent_seconds, 0)


class TestTriageRuns(unittest.TestCase):
    """End-to-end runs, including the invariant that keeps scores honest."""

    def _run(self, budget: int, out: Path) -> dict:
        return run_triage(
            timeline_path=TIMELINE,
            budget_seconds=budget,
            policy_name="deterministic",
            out_dir=out,
            quiet=True,
        )

    def test_full_budget_converges_on_the_ground_truth(self) -> None:
        """The headline result: enough evidence removes every false claim."""
        truth = EvidenceTimeline(TIMELINE).ground_truth
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run(90_000, Path(tmp))
        claims = set(summary["orphan_claims"])
        self.assertEqual(claims, set(truth["orphaned_elements"]))
        self.assertFalse(claims & set(truth["used_elements"]))

    def test_starting_evidence_contains_false_claims(self) -> None:
        """Without more evidence, live surface looks like free hardening."""
        timeline = EvidenceTimeline(TIMELINE)
        weights, cve_map = load_curated()
        report = build_report(timeline.snapshot(timeline.start_window), weights, cve_map)
        false_claims = set(report["orphaned"]["elements"]) & set(
            timeline.ground_truth["used_elements"]
        )
        self.assertTrue(
            false_claims,
            "the starting snapshot must contain the failure mode being fixed",
        )

    def test_tight_budget_stops_early_and_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run(100, Path(tmp))
        self.assertEqual(summary["evidence_cost_seconds"], 0)
        self.assertLessEqual(summary["evidence_cost_seconds"], 100)
        self.assertTrue(summary["finalize_reason"])

    def test_budget_is_never_exceeded(self) -> None:
        for budget in (0, 100, 1000, 90_000):
            with tempfile.TemporaryDirectory() as tmp:
                summary = self._run(budget, Path(tmp))
            self.assertLessEqual(summary["evidence_cost_seconds"], budget)

    def test_report_is_a_pure_function_of_final_evidence(self) -> None:
        """AGENTS.md#the-agent-boundary, pinned.

        The agent chose which windows to buy. Given the window it stopped
        on, the report must be byte-identical to running the deterministic
        engine directly on that window - no agent influence on any number.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run(90_000, Path(tmp))
            agent_report = json.loads((Path(tmp) / "report.json").read_text())

        timeline = EvidenceTimeline(TIMELINE)
        weights, cve_map = load_curated()
        direct = build_report(timeline.snapshot(summary["final_window"]), weights, cve_map)

        self.assertEqual(
            json.dumps(agent_report["score"], sort_keys=True),
            json.dumps(direct["score"], sort_keys=True),
        )
        self.assertEqual(
            json.dumps(agent_report["orphaned"], sort_keys=True),
            json.dumps(direct["orphaned"], sort_keys=True),
        )
        self.assertEqual(
            json.dumps(agent_report["ledger"], sort_keys=True),
            json.dumps(direct["ledger"], sort_keys=True),
        )

    def test_run_is_reproducible_including_the_trajectory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first_dir, second_dir = Path(tmp) / "a", Path(tmp) / "b"
            self._run(90_000, first_dir)
            self._run(90_000, second_dir)
            for name in ("report.json", "trajectory.jsonl", "verification.json"):
                self.assertEqual(
                    (first_dir / name).read_text(),
                    (second_dir / name).read_text(),
                    f"{name} is not reproducible",
                )

    def test_run_writes_every_required_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self._run(90_000, out)
            for name in (
                "report.json",
                "trajectory.jsonl",
                "verification.json",
                "summary.json",
                "APPROVAL_REQUIRED.md",
            ):
                self.assertTrue((out / name).exists(), name)

    def test_trajectory_records_tools_rationale_and_the_human_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self._run(90_000, out)
            records = [
                json.loads(line)
                for line in (out / "trajectory.jsonl").read_text().splitlines()
                if line.strip()
            ]
        self.assertTrue(records)
        self.assertEqual([r["seq"] for r in records], list(range(1, len(records) + 1)))
        for record in records:
            self.assertIn("instructions_ref", record)
        tool_calls = [r for r in records if r.get("phase") == "tool_call"]
        self.assertTrue(tool_calls)
        for call in tool_calls:
            self.assertIn("tool", call)
            self.assertIn("observation", call)
            self.assertTrue(call.get("rationale"), "every step must justify itself")
        self.assertTrue(
            any(r.get("event") == "approval_gate" for r in records),
            "a human checkpoint must appear in the trajectory",
        )

    def test_nothing_is_ever_applied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run(90_000, Path(tmp))
        self.assertFalse(summary["applied_to_host"])


if __name__ == "__main__":
    unittest.main()
