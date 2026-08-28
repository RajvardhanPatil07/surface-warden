"""Baseline: static configuration checklist, no runtime evidence.

What every mainstream kernel hardening checker does: read the kernel
config, the loaded/available module list and the sysctls, compare against a
recommended set, and emit every deviation as a finding. It has no notion of
reachability gating, no notion of which workload holds surface open, and no
notion of whether anything is actually used.

It is given exactly the same snapshot and the same curated risk table as the
advanced solution, so the comparison is fair. The difference in output is a
difference in method, not in inputs.

Run directly:

    python -m baseline.checklist --raw fixtures/raw-demo.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from engine.attribution import cve_ids
from engine.reachability import DEV_PATHS, KCONFIG_PRESENCE, MODULE_MEMBERS

ROOT = Path(__file__).resolve().parent.parent

REMOVABLE_KINDS = frozenset({"syscall", "module", "devnode", "namespace", "capability"})

# The hardened value a config checker expects to see for each sysctl-backed
# element. A deviation is reported as a finding.
EXPECTED_SYSCTLS: dict[str, tuple[str, str]] = {
    "cfg.module_autoload": ("kernel.modules_disabled", "1"),
    "cfg.no_kptr_restrict": ("kernel.kptr_restrict", "2"),
    "cfg.dmesg_open": ("kernel.dmesg_restrict", "1"),
}


def _entries(weights: dict) -> list[dict]:
    """Flatten the curated weights table."""
    return sorted(
        (entry for group in weights.values() for entry in group),
        key=lambda e: e["id"],
    )


def _statically_present(entry: dict, raw: dict) -> bool:
    """Presence by configuration alone - no gating, no runtime evidence."""
    kind = entry["kind"]
    eid = entry["id"]

    if kind in {"syscall", "namespace", "kconfig"}:
        symbols = KCONFIG_PRESENCE.get(eid, (entry["name"],))
        return any(raw["kconfig"].get(symbol) == "y" for symbol in symbols)
    if kind == "module":
        members = MODULE_MEMBERS.get(eid, (entry["name"],))
        available = set(raw["modules_available"]) | {
            m["name"] for m in raw["modules_loaded"]
        }
        return any(member in available for member in members)
    if kind == "devnode":
        node = raw["devnodes"].get(DEV_PATHS.get(eid, ""))
        return bool(node and (node["nonroot_read"] or node["nonroot_write"]))
    if kind == "sysctl":
        key, expected = EXPECTED_SYSCTLS.get(eid, ("", ""))
        return bool(key) and raw["sysctls"].get(key) != expected
    if kind == "lsm":
        return "[none]" in str(raw.get("lockdown_state", ""))
    if kind == "capability":
        return any(
            "CAP_21" in w["caps_effective"] for w in raw["workloads"]
        )
    return False


def build_checklist(raw: dict, weights: dict, cve_map: dict) -> dict:
    """Return every static finding, with no usage or attribution model."""
    findings: list[dict] = []
    for entry in _entries(weights):
        if not _statically_present(entry, raw):
            continue
        mitigations = [str(m) for m in entry.get("mitigations", [])]
        findings.append(
            {
                "id": entry["id"],
                "kind": entry["kind"],
                "name": entry["name"],
                "weight": float(entry["weight"]),
                "cve_clusters": sorted(entry.get("cve_clusters", [])),
                "recommendation": mitigations[0] if mitigations else "review manually",
                "usage_evidence": None,
                "note": "static configuration finding; usage was not measured",
            }
        )

    # With no usage model, every removable finding is assumed removable.
    claims = sorted(f["id"] for f in findings if f["kind"] in REMOVABLE_KINDS)
    clusters = sorted({c for f in findings for c in f["cve_clusters"]})
    risk_removed = round(
        sum(f["weight"] for f in findings if f["kind"] in REMOVABLE_KINDS), 2
    )
    return {
        "method": "static configuration checklist",
        "observation_window_seconds": 0,
        "findings": findings,
        "claims_orphaned": claims,
        "score": {
            "findings": len(findings),
            "risk_removed": risk_removed,
            "cves_neutralizable": len(cve_ids(clusters, cve_map)),
        },
        "limitations": [
            "no reachability gating: a setting already blocked by a sysctl or "
            "lockdown is still reported",
            "no attribution: cannot say which workload holds any surface open",
            "no usage evidence: cannot distinguish unused surface from surface "
            "that a live workload depends on",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    """CLI: python -m baseline.checklist --raw fixtures/raw-demo.json"""
    from ksl import load_curated

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw", default=str(ROOT / "fixtures" / "raw-demo.json"), help="raw snapshot"
    )
    parser.add_argument("-o", "--output", help="write the checklist JSON here")
    args = parser.parse_args(argv)

    raw = json.loads(Path(args.raw).read_text())
    weights, cve_map = load_curated()
    checklist = build_checklist(raw, weights, cve_map)

    if args.output:
        Path(args.output).write_text(json.dumps(checklist, indent=2, sort_keys=True) + "\n")
        print(f"wrote {args.output}")
    print(f"baseline: static configuration checklist ({args.raw})")
    print(f"  findings            : {checklist['score']['findings']}")
    print(f"  assumed removable   : {len(checklist['claims_orphaned'])}")
    print(f"  risk weight claimed : {checklist['score']['risk_removed']}")
    print(f"  CVEs claimed        : {checklist['score']['cves_neutralizable']}")
    print("  usage measured      : no")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
