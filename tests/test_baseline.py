"""The baseline must be fair, and must fail the way real checkers fail.

A strawman baseline would make the advanced solution look good for the
wrong reason. These tests assert the baseline gets the same inputs and the
same curated risk table, and that its weakness is the documented,
structural one: no usage evidence.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.tools import EvidenceTimeline
from baseline.checklist import REMOVABLE_KINDS, build_checklist
from ksl import load_curated

TIMELINE = ROOT / "fixtures" / "timeline-demo.json"


class TestBaselineChecklist(unittest.TestCase):
    def setUp(self) -> None:
        self.weights, self.cve_map = load_curated()
        self.timeline = EvidenceTimeline(TIMELINE)
        self.raw = self.timeline.snapshot(self.timeline.start_window)
        self.checklist = build_checklist(self.raw, self.weights, self.cve_map)

    def test_produces_findings(self) -> None:
        self.assertTrue(self.checklist["findings"])
        for finding in self.checklist["findings"]:
            self.assertTrue(finding["recommendation"])
            self.assertGreaterEqual(finding["weight"], 0)

    def test_measures_no_usage_at_all(self) -> None:
        self.assertEqual(self.checklist["observation_window_seconds"], 0)
        for finding in self.checklist["findings"]:
            self.assertIsNone(finding["usage_evidence"])

    def test_claims_only_removable_kinds(self) -> None:
        kinds = {
            f["kind"] for f in self.checklist["findings"]
            if f["id"] in set(self.checklist["claims_orphaned"])
        }
        self.assertTrue(kinds.issubset(REMOVABLE_KINDS))

    def test_uses_the_same_curated_weights(self) -> None:
        """Fairness: no invented weights, same table as the engine."""
        curated = {
            entry["id"]: float(entry["weight"])
            for group in self.weights.values()
            for entry in group
        }
        for finding in self.checklist["findings"]:
            self.assertEqual(finding["weight"], curated[finding["id"]])

    def test_claims_surface_that_is_actually_live(self) -> None:
        """The structural weakness: no usage model means false positives."""
        used = set(self.timeline.ground_truth["used_elements"])
        self.assertTrue(
            set(self.checklist["claims_orphaned"]) & used,
            "a usage-blind checklist must claim live surface is removable",
        )

    def test_documents_its_own_limitations(self) -> None:
        self.assertGreaterEqual(len(self.checklist["limitations"]), 3)

    def test_is_deterministic(self) -> None:
        again = build_checklist(self.raw, self.weights, self.cve_map)
        self.assertEqual(
            json.dumps(self.checklist, sort_keys=True),
            json.dumps(again, sort_keys=True),
        )


if __name__ == "__main__":
    unittest.main()
