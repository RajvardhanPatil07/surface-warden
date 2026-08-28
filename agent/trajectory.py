"""JSONL trajectory writer.

One line per agent step, from the agent instructions through to the final
result: what the agent did, how the tool responded, what it decided next,
and every retry or human checkpoint along the way.

Timestamps are deterministic by default (`t+0001`, `t+0002`, ...) so two
runs over the same evidence produce byte-identical trajectories and can be
diffed in review. Pass `wall_clock=True` for real timestamps when
recording a live demo.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class Trajectory:
    """Append-only JSONL record of one agent run."""

    def __init__(
        self,
        path: str | Path,
        agent: str,
        instructions_ref: str,
        wall_clock: bool = False,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("")
        self.agent = agent
        self.instructions_ref = instructions_ref
        self.wall_clock = wall_clock
        self.seq = 0
        self.records: list[dict] = []
        self.record(
            phase="start",
            event="agent_instructions",
            detail=(
                "Agent may acquire read-only evidence only. It may not choose a "
                "weight, a score, a plan ordering, or apply any artifact."
            ),
        )

    def _timestamp(self) -> str:
        """Deterministic sequence stamp, or a real timestamp on request."""
        if self.wall_clock:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return f"t+{self.seq:04d}"

    def record(self, **fields: object) -> dict:
        """Write one trajectory step and return it."""
        self.seq += 1
        entry: dict = {
            "seq": self.seq,
            "ts": self._timestamp(),
            "agent": self.agent,
            "instructions_ref": self.instructions_ref,
        }
        entry.update({key: value for key, value in fields.items() if value is not None})
        with self.path.open("a") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        self.records.append(entry)
        return entry

    def summary(self) -> dict:
        """Counts a reviewer wants without reading the whole file."""
        return {
            "path": str(self.path),
            "steps": len(self.records),
            "tool_calls": sum(1 for r in self.records if r.get("phase") == "tool_call"),
            "retries": sum(1 for r in self.records if r.get("retry_of") is not None),
            "human_checkpoints": sum(
                1 for r in self.records if r.get("phase") == "human_checkpoint"
            ),
            "policy_fallbacks": sum(
                1 for r in self.records if r.get("event") == "policy_fallback"
            ),
        }
