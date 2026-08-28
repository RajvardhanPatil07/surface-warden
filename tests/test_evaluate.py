"""The improvement must be measured, monotone, and reproducible.

The claim being tested is not "the advanced solution is better". It is the
specific, falsifiable one: buying more observation evidence monotonically
reduces false orphan claims, and the agent converges on the held-out
ground truth.
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

from evaluation.harness import render_markdown, run_evaluation

TIMELINE = ROOT / "fixtures" / "timeline-demo.json"

ARMS = (
    "baseline_static_checklist",
    "advanced_single_shot",
    "advanced_agent_budget_1000",
    "advanced_agent_budget_90000",
)


class TestEvaluation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.result = run_evaluation(TIMELINE, Path(cls._tmp.name))
        cls.arms = cls.result["arms"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_every_arm_is_scored(self) -> None:
        for name in ARMS:
            self.assertIn(name, self.arms)

    def test_false_orphans_fall_as_evidence_is_bought(self) -> None:
        counts = [self.arms[name]["false_orphans"] for name in ARMS]
        self.assertEqual(
            counts,
            sorted(counts, reverse=True),
            f"false orphans must not increase with more evidence: {counts}",
        )

    def test_agent_removes_every_false_claim(self) -> None:
        best = self.arms["advanced_agent_budget_90000"]
        self.assertEqual(best["false_orphans"], 0, best["false_orphan_ids"])
        self.assertEqual(best["breakage_incidents"], 0, best["elements_broken"])
        self.assertEqual(best["precision"], 1.0)

    def test_baseline_would_break_live_surface(self) -> None:
        """The cost of no usage model, in outages."""
        baseline = self.arms["baseline_static_checklist"]
        self.assertGreater(baseline["breakage_incidents"], 0)
        self.assertGreater(baseline["false_orphans"], 0)

    def test_agent_is_more_efficient_than_the_baseline(self) -> None:
        baseline = self.arms["baseline_static_checklist"]
        best = self.arms["advanced_agent_budget_90000"]
        self.assertGreater(
            best["safe_risk_per_breakage_cost"],
            baseline["safe_risk_per_breakage_cost"],
        )

    def test_evidence_spend_is_reported_and_bounded(self) -> None:
        self.assertEqual(self.arms["baseline_static_checklist"]["evidence_cost_seconds"], 0)
        self.assertEqual(self.arms["advanced_single_shot"]["evidence_cost_seconds"], 0)
        self.assertLessEqual(
            self.arms["advanced_agent_budget_1000"]["evidence_cost_seconds"], 1000
        )
        self.assertLessEqual(
            self.arms["advanced_agent_budget_90000"]["evidence_cost_seconds"], 90_000
        )

    def test_more_evidence_costs_more(self) -> None:
        """Correctness is bought, not free. The table must show the price."""
        self.assertGreater(
            self.arms["advanced_agent_budget_90000"]["evidence_cost_seconds"],
            self.arms["advanced_agent_budget_1000"]["evidence_cost_seconds"],
        )

    def test_artifacts_are_written(self) -> None:
        out = Path(self._tmp.name)
        self.assertTrue((out / "comparison.json").exists())
        self.assertTrue((out / "comparison.md").exists())

    def test_markdown_names_every_arm(self) -> None:
        markdown = render_markdown(self.result)
        for name in ARMS:
            self.assertIn(name, markdown)

    def test_evaluation_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            again = run_evaluation(TIMELINE, Path(tmp))
        self.assertEqual(
            json.dumps(self.result["arms"], sort_keys=True),
            json.dumps(again["arms"], sort_keys=True),
        )


if __name__ == "__main__":
    unittest.main()
