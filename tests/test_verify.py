"""Artifact self-verification: catch it, repair it, or explain it.

A plan step that generates a file which silently does nothing is worse
than no recommendation. Each test below is a real way these artifact
formats fail in production.
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
from agent.verify import repair, verify_plan, verify_step
from engine.report import build_report
from ksl import load_curated

TIMELINE = ROOT / "fixtures" / "timeline-demo.json"


def step(action: str, targets: list[str], content: str, reboot: bool = False) -> dict:
    """Minimal plan step shaped like the engine's output."""
    return {
        "step": 1,
        "action": action,
        "targets": targets,
        "requires_reboot": reboot,
        "artifact": {"path": f"/tmp/{action}", "content": content},
    }


class TestArtifactDefects(unittest.TestCase):
    def test_blacklist_without_install_override_is_caught(self) -> None:
        """blacklist alone does not stop explicit insertion or autoload."""
        bad = step("blacklist_module", ["dccp"], "# generated\nblacklist dccp\n")
        result = verify_step(bad)
        self.assertFalse(result["ok"])
        self.assertTrue(any("install dccp" in e for e in result["errors"]))

        fixed, applied = repair(bad)
        self.assertTrue(applied)
        self.assertTrue(verify_step(fixed)["ok"])
        self.assertIn("install dccp /bin/false", fixed["artifact"]["content"])

    def test_sysctl_weaker_than_hardened_value_is_caught(self) -> None:
        bad = step(
            "sysctl_set",
            ["kernel.kptr_restrict=2"],
            "# generated\nkernel.kptr_restrict = 1\n",
        )
        result = verify_step(bad)
        self.assertFalse(result["ok"])
        self.assertTrue(any("weaker" in e for e in result["errors"]))

        fixed, applied = repair(bad)
        self.assertTrue(applied)
        self.assertTrue(verify_step(fixed)["ok"])
        self.assertIn("kernel.kptr_restrict = 2", fixed["artifact"]["content"])

    def test_unparseable_sysctl_line_is_caught(self) -> None:
        bad = step("sysctl_set", ["x"], "# generated\nkernel.kptr_restrict 2\n")
        self.assertFalse(verify_step(bad)["ok"])

    def test_invalid_seccomp_json_is_caught_and_rebuilt(self) -> None:
        bad = step(
            "seccomp_filter",
            ["userfaultfd"],
            "# deny listed syscalls\n{ not valid json",
        )
        result = verify_step(bad)
        self.assertFalse(result["ok"])

        fixed, applied = repair(bad)
        self.assertTrue(applied)
        self.assertTrue(verify_step(fixed)["ok"])
        body = "\n".join(
            line
            for line in fixed["artifact"]["content"].splitlines()
            if not line.strip().startswith("#")
        )
        profile = json.loads(body)
        self.assertIn("userfaultfd", profile["syscalls"][0]["names"])
        self.assertIsInstance(profile["syscalls"][0]["errnoRet"], int)

    def test_seccomp_without_errno_is_caught(self) -> None:
        bad = step(
            "seccomp_filter",
            ["userfaultfd"],
            "# deny\n"
            + json.dumps(
                {
                    "defaultAction": "SCMP_ACT_ALLOW",
                    "syscalls": [
                        {"names": ["userfaultfd"], "action": "SCMP_ACT_ERRNO"}
                    ],
                }
            ),
        )
        self.assertFalse(verify_step(bad)["ok"])
        fixed, _ = repair(bad)
        self.assertTrue(verify_step(fixed)["ok"])

    def test_systemd_dropin_without_service_section_is_caught(self) -> None:
        bad = step("systemd_confine", ["nginx.service"], "NoNewPrivileges=yes\n")
        self.assertFalse(verify_step(bad)["ok"])
        fixed, _ = repair(bad)
        self.assertTrue(verify_step(fixed)["ok"])
        self.assertIn("[Service]", fixed["artifact"]["content"])

    def test_udev_rule_without_mode_is_caught(self) -> None:
        bad = step(
            "remove_devnode_access",
            ["/dev/kvm"],
            '# generated\nKERNEL=="kvm", GROUP="kvm"\n',
        )
        self.assertFalse(verify_step(bad)["ok"])
        fixed, _ = repair(bad)
        self.assertTrue(verify_step(fixed)["ok"])

    def test_repair_is_idempotent(self) -> None:
        bad = step("blacklist_module", ["dccp"], "# generated\nblacklist dccp\n")
        once, _ = repair(bad)
        twice, applied = repair(once)
        self.assertEqual(once["artifact"]["content"], twice["artifact"]["content"])
        self.assertEqual(applied, [])


class TestVerifyRealPlan(unittest.TestCase):
    """Whatever the templates emit, every failure must be explained."""

    def setUp(self) -> None:
        weights, cve_map = load_curated()
        timeline = EvidenceTimeline(TIMELINE)
        self.report = build_report(
            timeline.snapshot(timeline.start_window), weights, cve_map
        )

    def test_every_plan_step_is_checked(self) -> None:
        result = verify_plan(self.report["plan"])
        self.assertEqual(result["artifacts_checked"], len(self.report["plan"]))
        self.assertGreater(result["artifacts_checked"], 0)

    def test_every_failure_carries_a_reason(self) -> None:
        result = verify_plan(self.report["plan"])
        for entry in result["results"]:
            if not entry["ok"]:
                self.assertTrue(
                    entry["errors"], "a failing artifact must say what is wrong"
                )

    def test_validity_rate_is_reported(self) -> None:
        result = verify_plan(self.report["plan"])
        self.assertGreaterEqual(result["validity_rate"], 0.0)
        self.assertLessEqual(result["validity_rate"], 1.0)

    def test_verification_is_deterministic(self) -> None:
        weights, cve_map = load_curated()
        timeline = EvidenceTimeline(TIMELINE)
        first = verify_plan(
            build_report(timeline.snapshot(timeline.start_window), weights, cve_map)["plan"]
        )
        second = verify_plan(
            build_report(timeline.snapshot(timeline.start_window), weights, cve_map)["plan"]
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )


if __name__ == "__main__":
    unittest.main()
