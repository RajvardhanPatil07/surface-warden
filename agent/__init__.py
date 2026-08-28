"""Evidence-acquisition agent for surface-warden.

The deterministic engine in `engine/` owns every score, weight, gate and
plan ordering. This package owns exactly one decision: *which read-only
evidence is worth acquiring before a hardening claim is trusted*.

That split is the whole design. Scores stay reproducible and auditable;
judgment is applied where the evidence is genuinely incomplete.
"""

WARDEN_AGENT_VERSION = "1.0.0"
