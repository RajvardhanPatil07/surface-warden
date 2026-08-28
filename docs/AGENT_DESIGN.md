# Agent design

## The judgment call this agent exists to make

`surface-warden` decides whether reachable kernel surface is safe to remove.
The deterministic engine can do that perfectly *given the evidence*, and the
evidence is the problem:

> `used` means "observed during the observation window".

A 60-second midday trace cannot see a job that runs every 15 minutes, and it
certainly cannot see a job that runs at 02:30. So the engine faces two
failure modes it cannot resolve on its own:

- **No tracer at all.** Usage is *unknown*, not absent. The engine correctly
  refuses to call syscall surface orphaned, and therefore under-reports.
- **A short tracer window.** Usage looks absent when it is merely unobserved.
  The engine over-reports, and recommends removing surface a live workload
  depends on. That is an outage, not a hardening win.

Buying more observation time fixes both, and costs real money and real
wall-clock time. **Deciding which evidence is worth buying, and when the
answer has stopped changing, is the judgment call.** It is not cosmetic: get
it wrong in one direction and you break production, get it wrong in the other
and you leave exploitable surface in place.

It is also checkable, which is why it is worth automating rather than
narrating.

## The boundary

| The agent may decide | The agent may never decide |
| --- | --- |
| Which observation window to acquire next | Any weight, gate, score, or CVE mapping |
| When to stop acquiring evidence | Which mitigation to recommend, or in what order |
| Which claims to cross-check against raw evidence | Whether to add or drop a plan step |
| When to hand off to a human | Whether to apply anything |

The invariant, pinned by `tests/test_agent_evidence.py`:

> The report is a pure function of the final evidence set.

Two runs that end on the same evidence produce identical reports, whichever
policy chose that evidence and whether or not a model was in the loop. The
blast radius of a bad agent decision is bounded to *bought too much or too
little observation time* - a cost error, never a correctness error.

This is why the agent is trustworthy enough to ship: it cannot lie about
security numbers, because it cannot touch them.

## Tool surface

All read-only, all pure functions of the evidence timeline.

| Tool | Purpose | Cost |
| --- | --- | --- |
| `describe_evidence` | Current window, backend, spend, what else is available | free |
| `list_orphan_claims` | Elements currently claimed orphaned, with weight | free |
| `crosscheck_claim` | Raw evidence behind one claim: gate reason, touchers, module instances | free |
| `request_trace_window` | Acquire a longer observation window | charged |
| `score_current` | Deterministic headline score for current evidence | free |
| `finalize` | Stop, and record why | free |

The timeline's `ground_truth` block is unreachable from every tool. The agent
is scored against evidence it was never allowed to see, and there is a test
asserting no tool output can leak it.

## The stop rule

The hard part of an evidence-acquisition agent is not acquiring evidence, it
is stopping. The deterministic policy, in priority order:

1. **Never trust a claim set with no tracer**, or with a window too short to
   have observed a periodic workload even once (`< 900s`).
2. **If the last escalation changed the claim set, the set has not
   converged.** Keep buying while the budget allows. A claim set that is
   still moving is not safe to act on.
3. **Once stable, cross-check every surviving claim** against raw evidence
   before a human is asked to approve removing it.
4. **Otherwise finalize**, recording which constraint ended the run:
   convergence, or budget.

Convergence-based stopping is what makes the result honest. The agent does not
stop when it has "enough" evidence by some fixed threshold; it stops when more
evidence stops changing the answer, or when it can no longer afford to find
out - and it says which.

## Two policies, same menu

- **`deterministic`** (default) implements the stop rule above. No API key, so
  the headline result reproduces offline on a judge's machine, and the
  evaluation has a fair non-random control.
- **`llm`** asks a model to choose the next tool call from the same menu and
  the same state JSON. Every reply is validated: malformed JSON, an unknown
  tool, bad argument types, or an unaffordable request all fall back to the
  deterministic policy.

**Fallbacks are logged, not hidden.** Each one is written to the trajectory as
a retry with `event: policy_fallback` and the reason the model was overruled.
A reviewer can count exactly how often the model was trusted.

Running the same evidence through either policy yields the same report, which
is the boundary invariant doing its job.

## Artifact self-verification

An agent that emits a plausible-looking config file which silently does
nothing is worse than one that emits nothing. Every generated artifact is
parsed and checked against the semantics of its own format before a human
sees it:

| Artifact | A real failure it catches |
| --- | --- |
| `modprobe.d` | `blacklist X` without `install X /bin/false` - does not stop explicit insertion or autoload |
| `sysctl.d` | A value weaker than the hardened target, or a line that does not parse |
| seccomp JSON | Invalid JSON, empty `names`, missing integer `errnoRet` |
| systemd drop-in | No `[Service]` header, so systemd ignores the file entirely |
| udev rule | No `MODE=`, so permissions are unchanged |
| kconfig fragment | Does not actually disable the symbol |

Failures are repaired deterministically and re-verified, up to two attempts.
Every attempt - the original failure, the repair applied, the re-check - is a
trajectory record. Anything unrepairable is reported with its reason rather
than quietly passed.

Verification is static parsing, not host mutation, which is why it runs
identically on a laptop, in CI, and in a judge's clean container.

## The human checkpoint

The run ends at an approval gate, not an action:

- a trajectory record with `status: pending_human_approval`
- `APPROVAL_REQUIRED.md`, listing every step with its artifact, breakage note,
  detection command and revert
- `warden.py --apply` **refuses by design** and explains why

There is no code path in this repository that applies a hardening change to a
host. Kernel hardening applied without review is how you lose a fleet, and
the rule book requires consequential actions to run behind human approval.

## Determinism

Trajectory timestamps are sequence stamps (`t+0001`) by default rather than
wall-clock times, so two runs over the same evidence produce byte-identical
trajectories that can be diffed in review. `--wall-clock` opts into real
timestamps for a live demo.

## What would break at scale

Honest limits, since a reviewer will find them anyway:

- **The timeline is replayed, not live.** A real deployment needs a tracer
  scheduler that actually holds a `bcc` probe open for 24 hours, with the
  overhead that implies on a busy host.
- **Ground truth exists only in the fixture.** On a real host, "is this
  really unused?" is answered by change-management review and a longer
  soak, not by an answer key. The fixture makes the *method* measurable; it
  does not make the method omniscient.
- **The 900-second confidence floor is a curated constant**, chosen because
  it covers a standard metrics scrape cycle. A fleet with different
  periodicity needs a different floor, and that number belongs in
  `data/`, curated by a human, alongside the weights.
- **Cross-checking is per-claim and linear.** On a host with hundreds of
  claims this becomes the dominant step count and should be batched.
