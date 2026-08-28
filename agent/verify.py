"""Self-verification of generated hardening artifacts, with repair and retry.

A plan step that reads well but generates a broken artifact is worse than
no recommendation: it burns operator trust. Every artifact is parsed and
checked against the semantics of its own file format before a human is
asked to look at it. Failures are repaired deterministically and
re-verified, and each attempt is written to the trajectory.

Nothing here touches a host. Verification is static parsing of generated
text, which is why it runs identically on a laptop, in CI, and on a judge's
clean container.
"""

from __future__ import annotations

import json
import re

HARDENED_SYSCTL_VALUES: dict[str, str] = {
    "kernel.dmesg_restrict": "1",
    "kernel.io_uring_disabled": "2",
    "kernel.kptr_restrict": "2",
    "kernel.modules_disabled": "1",
    "kernel.perf_event_paranoid": "3",
    "kernel.unprivileged_bpf_disabled": "1",
    "kernel.unprivileged_userns_clone": "0",
    "vm.unprivileged_userfaultfd": "0",
}

SYSCTL_LINE = re.compile(r"^([a-z][\w.]+)\s*=\s*(\S+)$")


def _lines(content: str) -> list[str]:
    """Non-empty, non-comment lines."""
    return [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _check_blacklist(step: dict) -> list[str]:
    """A blacklist without an install override does not stop autoload."""
    content = step["artifact"]["content"]
    errors: list[str] = []
    for target in step["targets"]:
        if f"blacklist {target}" not in content:
            errors.append(f"missing 'blacklist {target}'")
        if f"install {target} /bin/false" not in content:
            errors.append(
                f"missing 'install {target} /bin/false': blacklist alone does not "
                "prevent explicit insertion or autoload"
            )
    return errors


def _check_sysctl(step: dict) -> list[str]:
    """Every setting must parse and must move in the hardening direction."""
    errors: list[str] = []
    settings = _lines(step["artifact"]["content"])
    if not settings:
        return ["artifact contains no sysctl settings"]
    for line in settings:
        match = SYSCTL_LINE.match(line)
        if not match:
            errors.append(f"unparseable sysctl line: {line!r}")
            continue
        key, value = match.group(1), match.group(2)
        expected = HARDENED_SYSCTL_VALUES.get(key)
        if expected is None:
            errors.append(f"unknown sysctl key {key}")
        elif value != expected:
            errors.append(f"{key}={value} is weaker than the hardened value {expected}")
    return errors


def _check_seccomp(step: dict) -> list[str]:
    """The profile must be valid JSON and actually deny something."""
    content = step["artifact"]["content"]
    body = "\n".join(
        line for line in content.splitlines() if not line.strip().startswith("#")
    ).strip()
    if not body:
        return ["seccomp artifact has no JSON body"]
    try:
        profile = json.loads(body)
    except json.JSONDecodeError as exc:
        return [f"seccomp profile is not valid JSON: {exc}"]
    errors: list[str] = []
    if profile.get("defaultAction") not in {"SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO"}:
        errors.append(f"invalid defaultAction {profile.get('defaultAction')!r}")
    rules = profile.get("syscalls")
    if not isinstance(rules, list) or not rules:
        return errors + ["seccomp profile denies no syscalls"]
    for rule in rules:
        if not rule.get("names"):
            errors.append("seccomp rule has an empty names list")
        if rule.get("action") != "SCMP_ACT_ERRNO":
            errors.append(f"unexpected seccomp action {rule.get('action')!r}")
        if not isinstance(rule.get("errnoRet"), int):
            errors.append("seccomp rule is missing an integer errnoRet")
    return errors


def _check_systemd(step: dict) -> list[str]:
    """A drop-in without a [Service] header is silently ignored by systemd."""
    content = step["artifact"]["content"]
    errors: list[str] = []
    if "[Service]" not in content:
        errors.append("drop-in has no [Service] section, so systemd ignores it")
    for directive in ("NoNewPrivileges=yes", "RestrictNamespaces=yes"):
        if directive not in content:
            errors.append(f"missing directive {directive}")
    return errors


def _check_udev(step: dict) -> list[str]:
    """A udev rule needs a match, a group and a mode to have any effect."""
    content = step["artifact"]["content"]
    errors: list[str] = []
    if 'KERNEL=="' not in content:
        errors.append("udev rule has no KERNEL== match")
    if 'GROUP="' not in content:
        errors.append("udev rule sets no GROUP")
    if 'MODE="' not in content:
        errors.append("udev rule sets no MODE, so permissions are unchanged")
    return errors


def _check_kconfig(step: dict) -> list[str]:
    """Config fragments must use the 'is not set' form to actually disable."""
    content = step["artifact"]["content"]
    if "CONFIG_" not in content:
        return ["kconfig fragment names no CONFIG_ symbol"]
    if "is not set" not in content and "=n" not in content:
        return ["kconfig fragment does not disable any symbol"]
    return []


CHECKS = {
    "blacklist_module": _check_blacklist,
    "sysctl_set": _check_sysctl,
    "seccomp_filter": _check_seccomp,
    "systemd_confine": _check_systemd,
    "remove_devnode_access": _check_udev,
    "kconfig_disable": _check_kconfig,
}


# ----------------------------------------------------------------------
# deterministic repair


def repair(step: dict) -> tuple[dict, list[str]]:
    """Fix mechanically-fixable artifact defects; report what was changed."""
    action = step["action"]
    content = step["artifact"]["content"]
    applied: list[str] = []

    if action == "blacklist_module":
        for target in step["targets"]:
            if f"blacklist {target}" not in content:
                content = content.rstrip("\n") + f"\nblacklist {target}\n"
                applied.append(f"added blacklist {target}")
            if f"install {target} /bin/false" not in content:
                content = content.rstrip("\n") + f"\ninstall {target} /bin/false\n"
                applied.append(f"added install override for {target}")

    elif action == "sysctl_set":
        rebuilt: list[str] = []
        for line in content.splitlines():
            match = SYSCTL_LINE.match(line.strip())
            if match and match.group(1) in HARDENED_SYSCTL_VALUES:
                key = match.group(1)
                hardened = HARDENED_SYSCTL_VALUES[key]
                if match.group(2) != hardened:
                    applied.append(f"raised {key} to {hardened}")
                rebuilt.append(f"{key} = {hardened}")
            else:
                rebuilt.append(line)
        content = "\n".join(rebuilt).rstrip("\n") + "\n"

    elif action == "seccomp_filter":
        body = "\n".join(
            line for line in content.splitlines() if not line.strip().startswith("#")
        ).strip()
        try:
            profile = json.loads(body) if body else {}
        except json.JSONDecodeError:
            profile = {}
        if not isinstance(profile, dict) or not profile.get("syscalls"):
            names = sorted(t for t in step["targets"] if not t.startswith("/"))
            profile = {
                "defaultAction": "SCMP_ACT_ALLOW",
                "syscalls": [
                    {"names": names, "action": "SCMP_ACT_ERRNO", "errnoRet": 38}
                ],
            }
            applied.append("rebuilt seccomp profile from plan targets")
        else:
            profile.setdefault("defaultAction", "SCMP_ACT_ALLOW")
            for rule in profile["syscalls"]:
                rule.setdefault("action", "SCMP_ACT_ERRNO")
                if not isinstance(rule.get("errnoRet"), int):
                    rule["errnoRet"] = 38
                    applied.append("set errnoRet=38 (ENOSYS)")
        header = next(
            (line for line in content.splitlines() if line.strip().startswith("#")),
            "# deny listed syscalls via OCI seccomp",
        )
        content = header + "\n" + json.dumps(profile, indent=2, sort_keys=True) + "\n"

    elif action == "systemd_confine":
        if "[Service]" not in content:
            content = content.rstrip("\n") + "\n[Service]\n"
            applied.append("added [Service] section")
        for directive in ("NoNewPrivileges=yes", "RestrictNamespaces=yes"):
            if directive not in content:
                content = content.rstrip("\n") + f"\n{directive}\n"
                applied.append(f"added {directive}")

    elif action == "remove_devnode_access":
        if 'MODE="' not in content:
            content = content.rstrip("\n") + '\nMODE="0660"\n'
            applied.append("added MODE=0660")

    repaired = json.loads(json.dumps(step))
    repaired["artifact"]["content"] = content
    return repaired, applied


def verify_step(step: dict) -> dict:
    """Run the format-specific checks for one plan step."""
    check = CHECKS.get(step["action"])
    if check is None:
        return {
            "step": step["step"],
            "action": step["action"],
            "ok": False,
            "errors": [f"no verifier for action {step['action']}"],
        }
    errors = check(step)
    return {
        "step": step["step"],
        "action": step["action"],
        "ok": not errors,
        "checks_run": check.__name__,
        "errors": errors,
    }


def verify_plan(
    plan: list[dict],
    trajectory=None,
    max_retries: int = 2,
) -> dict:
    """Verify, repair and re-verify every artifact in a plan.

    Returns the verification record and the (possibly repaired) plan. The
    plan is mutated in place so the written report carries the artifacts
    that actually passed verification.
    """
    results: list[dict] = []
    repairs = 0

    for index, step in enumerate(plan):
        attempt = 0
        result = verify_step(step)
        if trajectory is not None:
            trajectory.record(
                phase="verification",
                event="verify_artifact",
                tool="verify_step",
                target=step["artifact"]["path"],
                attempt=attempt,
                observation={"ok": result["ok"], "errors": result["errors"]},
            )
        first_errors = list(result["errors"])

        while not result["ok"] and attempt < max_retries:
            attempt += 1
            repaired, applied = repair(step)
            if not applied:
                break
            plan[index] = repaired
            step = repaired
            repairs += 1
            result = verify_step(step)
            if trajectory is not None:
                trajectory.record(
                    phase="verification",
                    event="repair_and_reverify",
                    tool="repair",
                    target=step["artifact"]["path"],
                    attempt=attempt,
                    retry_of=f"verify:{step['step']}",
                    decision=f"applied {len(applied)} deterministic repair(s)",
                    repairs=applied,
                    observation={"ok": result["ok"], "errors": result["errors"]},
                )

        result["attempts"] = attempt + 1
        result["errors_before_repair"] = first_errors
        results.append(result)

    passed = sum(1 for r in results if r["ok"])
    return {
        "artifacts_checked": len(results),
        "artifacts_passed": passed,
        "validity_rate": round(passed / len(results), 3) if results else 1.0,
        "repairs_applied": repairs,
        "results": results,
    }
