#!/usr/bin/env python3
"""surface-warden CLI: evidence-aware kernel surface triage.

    python warden.py triage                 # agent acquires evidence, then reports
    python warden.py baseline               # static configuration checklist
    python warden.py evaluate               # baseline vs advanced comparison
    python warden.py verify --report r.json # re-verify a report's artifacts

The original single-shot scanner is unchanged and still available as
`python ksl.py scan`. This CLI is the competition entry point.

surface-warden never applies a hardening change. It produces artifacts,
detection commands and reverts for a human to review.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def cmd_triage(args: argparse.Namespace) -> int:
    """Run the evidence-acquisition agent, then score deterministically."""
    from agent.loop import run_triage

    run_triage(
        timeline_path=args.timeline,
        budget_seconds=args.budget,
        policy_name=args.policy,
        out_dir=args.out,
        explain=args.explain,
        wall_clock=args.wall_clock,
    )
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    """Run the static configuration checklist baseline."""
    from baseline.checklist import main as baseline_main

    argv = ["--raw", args.raw]
    if args.output:
        argv += ["-o", args.output]
    return baseline_main(argv)


def cmd_evaluate(args: argparse.Namespace) -> int:
    """Run every arm and write the comparison."""
    from evaluation.harness import main as evaluate_main

    return evaluate_main(["--timeline", args.timeline, "--out", args.out])


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify the artifacts of an existing report."""
    from agent.verify import verify_plan

    report = json.loads(Path(args.report).read_text())
    result = verify_plan(report["plan"])
    for entry in result["results"]:
        status = "ok" if entry["ok"] else "FAIL"
        print(f"  step {entry['step']:>2} {entry['action']:<22} {status}")
        for error in entry["errors"]:
            print(f"      - {error}")
    print(
        f"\n{result['artifacts_passed']}/{result['artifacts_checked']} artifacts valid "
        f"({result['repairs_applied']} repaired)"
    )
    return 0 if result["artifacts_passed"] == result["artifacts_checked"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden", description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="not supported: surface-warden never applies a hardening change",
    )
    sub = parser.add_subparsers(dest="command")

    triage = sub.add_parser("triage", help="acquire evidence, then score and plan")
    triage.add_argument("--timeline", default=str(ROOT / "fixtures" / "timeline-demo.json"))
    triage.add_argument("--budget", type=int, default=90_000,
                        help="observation seconds the agent may spend")
    triage.add_argument("--policy", default="deterministic",
                        choices=("deterministic", "llm"))
    triage.add_argument("--out", default=str(ROOT / "artifacts" / "runs" / "latest"))
    triage.add_argument("--explain", action="store_true",
                        help="add LLM narration (never changes a number)")
    triage.add_argument("--wall-clock", action="store_true",
                        help="real timestamps instead of deterministic ones")
    triage.set_defaults(func=cmd_triage)

    base = sub.add_parser("baseline", help="static configuration checklist")
    base.add_argument("--raw", default=str(ROOT / "fixtures" / "raw-demo.json"))
    base.add_argument("-o", "--output")
    base.set_defaults(func=cmd_baseline)

    evaluate = sub.add_parser("evaluate", help="baseline vs advanced comparison")
    evaluate.add_argument("--timeline", default=str(ROOT / "fixtures" / "timeline-demo.json"))
    evaluate.add_argument("--out", default=str(ROOT / "artifacts" / "evaluation"))
    evaluate.set_defaults(func=cmd_evaluate)

    verify = sub.add_parser("verify", help="verify a report's artifacts")
    verify.add_argument("--report", required=True)
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)

    if args.apply:
        print(
            "refusing --apply: surface-warden is read-only by design.\n"
            "Every plan step ships an artifact, a detection command and a revert "
            "for a human operator to apply through normal change management.",
            file=sys.stderr,
        )
        return 2
    if args.command is None:
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
