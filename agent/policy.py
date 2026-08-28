"""Policies that decide which evidence to acquire next.

Two interchangeable policies, both restricted to the same tool menu:

- `DeterministicPolicy` implements an explicit, documented stop rule. It
  needs no API key, so the headline result is reproducible offline and the
  evaluation harness has a fair, non-random control.
- `LlmPolicy` asks a model to choose the next tool call from the same menu
  and the same state. Any malformed, unknown or unaffordable choice falls
  back to the deterministic policy, and the fallback is written to the
  trajectory as a retry rather than hidden.

Neither policy can touch a weight, a score, a plan ordering, or apply an
artifact. The widest possible blast radius of a bad decision here is
"bought too much or too little observation time".
"""

from __future__ import annotations

import json

from agent.tools import MIN_CONFIDENT_TRACE_SECONDS, TOOL_CONTRACTS


class DeterministicPolicy:
    """Escalate while the answer is still moving, then stop and explain why.

    Stop rule, in priority order:

    1. Never trust a claim set built with no tracer, or with a window too
       short to have seen a periodic workload once.
    2. If the last escalation changed the claim set, the set is not yet
       stable: keep buying evidence while the budget allows.
    3. Once the claim set is stable, cross-check every surviving claim
       against the raw evidence before signing off on it.
    4. Otherwise finalize, recording which constraint ended the run.
    """

    name = "deterministic"

    def next_action(self, state: dict) -> dict:
        affordable = state["affordable_windows"]
        window = affordable[0] if affordable else None

        if state["trace_backend"] == "none":
            if window:
                return {
                    "action": "request_trace_window",
                    "arguments": {"seconds": window["trace_seconds"]},
                    "rationale": (
                        "No tracer ran, so syscall usage is unknown rather than "
                        "absent. Acquire real usage evidence before claiming anything."
                    ),
                }
            return {
                "action": "finalize",
                "arguments": {
                    "reason": "no tracer and no affordable window: reporting config-only findings"
                },
                "rationale": "Cannot buy usage evidence; refuse to infer it.",
            }

        if state["trace_seconds"] < state["min_confident_trace_seconds"] and window:
            return {
                "action": "request_trace_window",
                "arguments": {"seconds": window["trace_seconds"]},
                "rationale": (
                    f"{state['trace_seconds']}s is below the "
                    f"{MIN_CONFIDENT_TRACE_SECONDS}s floor for observing a periodic "
                    "workload at least once."
                ),
            }

        if state["claims_changed"] and window:
            return {
                "action": "request_trace_window",
                "arguments": {"seconds": window["trace_seconds"]},
                "rationale": (
                    "The last longer window changed the claim set, so it has not "
                    "converged. A claim set that is still moving is not safe to act on."
                ),
            }

        unchecked = [
            eid for eid in state["orphan_claims"] if eid not in state["crosschecked"]
        ]
        if unchecked:
            return {
                "action": "crosscheck_claim",
                "arguments": {"element_id": unchecked[0]},
                "rationale": (
                    f"Claim set is stable; verify {unchecked[0]} against raw evidence "
                    "before a human is asked to approve removing it."
                ),
            }

        if state["claims_changed"] and not window:
            reason = (
                "claim set still changing but no affordable longer window: "
                "remaining claims flagged as budget-limited"
            )
        else:
            reason = (
                "claim set stable across the longest affordable window and every "
                "claim cross-checked"
            )
        return {
            "action": "finalize",
            "arguments": {"reason": reason},
            "rationale": "Further evidence would not change the decision.",
        }


PROMPT_HEADER = """You are the evidence-acquisition policy for a read-only Linux kernel
attack-surface analyzer.

A deterministic engine already owns every score, weight, CVE count and plan
ordering. You cannot change any of them. Your only job is to decide which
read-only evidence to acquire next, then stop.

The risk you are managing: `used` means "observed during the trace window".
A short window makes a periodic workload look unused, and recommending the
removal of surface a nightly job needs is a real outage. Buying observation
time costs budget. Spend it where a claim could be wrong.

Available tools:
{tools}

Reply with one JSON object and nothing else:
{{"action": "<tool name>", "arguments": {{...}}, "rationale": "<one sentence>"}}
"""


class LlmPolicy:
    """Model-chosen next action, validated, with deterministic fallback."""

    name = "llm"

    def __init__(self) -> None:
        self.fallback = DeterministicPolicy()
        self.last_fallback_reason: str | None = None

    def _prompt(self, state: dict) -> str:
        tools = "\n".join(f"- {n}: {d}" for n, d in sorted(TOOL_CONTRACTS.items()))
        return (
            PROMPT_HEADER.format(tools=tools)
            + "\nCurrent state:\n"
            + json.dumps(state, indent=2, sort_keys=True)
        )

    def next_action(self, state: dict) -> dict:
        """Ask the model; fall back to the stop rule on anything unusable."""
        self.last_fallback_reason = None
        from explain.explain import _cached_or_fetch

        answer = _cached_or_fetch(self._prompt(state))
        if answer is None:
            return self._fall_back(state, "no model configured or request failed")
        try:
            parsed = json.loads(answer.strip().removeprefix("```json").removesuffix("```").strip())
        except (json.JSONDecodeError, AttributeError):
            return self._fall_back(state, "model reply was not valid JSON")
        if not isinstance(parsed, dict):
            return self._fall_back(state, "model reply was not a JSON object")
        action = parsed.get("action")
        if action not in TOOL_CONTRACTS:
            return self._fall_back(state, f"model chose unavailable tool {action!r}")
        arguments = parsed.get("arguments")
        if arguments is not None and not isinstance(arguments, dict):
            return self._fall_back(state, "model arguments were not an object")
        return {
            "action": action,
            "arguments": arguments or {},
            "rationale": str(parsed.get("rationale", "")).strip(),
            "chosen_by": "llm",
        }

    def _fall_back(self, state: dict, reason: str) -> dict:
        """Record why the model was overruled and use the stop rule instead."""
        self.last_fallback_reason = reason
        action = self.fallback.next_action(state)
        action["chosen_by"] = "deterministic_fallback"
        action["fallback_reason"] = reason
        return action


def build_policy(name: str) -> DeterministicPolicy | LlmPolicy:
    """Resolve a policy by name."""
    if name == "llm":
        return LlmPolicy()
    if name == "deterministic":
        return DeterministicPolicy()
    raise ValueError(f"unknown policy {name!r}; expected 'deterministic' or 'llm'")
