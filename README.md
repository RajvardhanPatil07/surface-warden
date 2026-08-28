<div align="center">

# surface-warden

### Kernel hardening you can actually apply

**A read-only Linux analyzer that decides how much evidence it needs before it tells you to remove kernel attack surface.**

[![Read-only](https://img.shields.io/badge/collector-read--only-0f766e?style=flat-square&logo=linux&logoColor=white)](#safety-boundary)
[![Deterministic scoring](https://img.shields.io/badge/scoring-deterministic-d97706?style=flat-square)](#the-agent-boundary)
[![Reproducible offline](https://img.shields.io/badge/reproduces-offline%20%C2%B7%20no%20API%20key-2563eb?style=flat-square)](docs/REPRODUCE.md)
[![MIT License](https://img.shields.io/badge/license-MIT-64748b?style=flat-square)](LICENSE)

[Agent design](docs/AGENT_DESIGN.md) &nbsp;·&nbsp; [Improvement changelog](docs/IMPROVEMENT_CHANGELOG.md) &nbsp;·&nbsp; [Reproduce it](docs/REPRODUCE.md) &nbsp;·&nbsp; [Prior art](docs/PRIOR_ART.md)

</div>

---

## The user and the bottleneck

**Who this is for:** the engineer who owns a fleet of Linux hosts and has a
kernel-hardening ticket assigned to them - a platform or infrastructure
security engineer, working against a CIS or KSPP checklist and a change window.

**Their bottleneck is not finding issues.** A configuration checker finds
hundreds in seconds. The bottleneck is deciding **which of those are safe to
apply**, because the cost of the two mistakes is wildly asymmetric:

- Leave reachable surface in place and you keep an exploitable kernel.
- Disable surface a live workload depends on and you take down production at
  02:30, from a change that was labelled "hardening".

So the ticket stalls. Every tool in this space answers *is this setting
present*. None answers *will removing it break something* - which is the
question that actually blocks the change ticket.

**Why it matters:** unapplied hardening is worth nothing. A recommendation an
operator cannot safely act on is not a security improvement, it is a backlog
item.

---

## The frontier problem: the evidence is incomplete

`surface-warden` answers the breakage question by observing which workloads
actually hold surface open. That works - and it exposes a harder problem
underneath, which is where this project spends its effort:

> `used` means **"observed during the observation window"**.

A 60-second midday trace cannot see a job that runs every 15 minutes, and
definitely cannot see one that runs at 02:30. The deterministic engine cannot
fix this, because it can only score the evidence it was handed. It fails in
both directions:

| Evidence handed over | What the engine does | Consequence |
| --- | --- | --- |
| No tracer | Correctly refuses to call syscall surface unused | Under-reports; free hardening left on the table |
| 60-second trace | Reports unobserved surface as orphaned | Over-reports; recommends removing surface a live job needs |

In the committed demo evidence, the 60-second snapshot an operator would
hand over contains **two false claims**: `sc.perf_event_open` (used every 15
minutes by `node_exporter`) and `sc.userfaultfd` (used once nightly by the
02:30 CRIU backup). Both are recommended for removal. Both are incidents.

**Deciding which additional evidence to buy, at what cost, before trusting a
removal claim** is a judgment call with a real price attached, and it is
checkable against ground truth. That is the decision this project hands to an
agent - and the only one.

---

## Baseline vs advanced

Four arms, identical host snapshot, identical curated risk table, scored
against a held-out answer key the agent cannot reach.

| | **baseline**<br>static checklist | **advanced**<br>single-shot | **advanced**<br>agent @ 1000s | **advanced**<br>agent @ 90000s |
| --- | --- | --- | --- | --- |
| Usage evidence used | none | 60s | 900s | 86400s |
| **False orphans** (live surface wrongly claimed removable) | highest by construction † | **2** | **1** | **0** |
| Matches ground truth exactly | no | no | no | **yes** |
| **Evidence cost** | 0s | 0s | 900s | 87300s |

† The baseline claims every statically-present removable element, so it has
the largest false-orphan count of the four by construction. Exact figures for
every cell, including risk removed and breakage cost, are generated - not
quoted by hand:

```bash
make evaluate    # writes artifacts/evaluation/comparison.{json,md}
```

The headline metric is **safe risk removed per unit of expected breakage
cost** - one number for "hardened the host without causing an outage". Every
arm is billed from the answer key for the outages its recommendations would
cause, so no arm gets credit for aggressive claims it cannot back up.

**Read the evidence-cost row before believing the false-orphan row.**
Correctness was bought, not discovered. Catching a nightly job costs a night,
and the harness reports that instead of hiding it. That is why the agent is
scored at two budgets: the improvement is a curve, not a trophy.

The direction of every one of these numbers is pinned by tests, not by
narration - see [expected output](docs/REPRODUCE.md#expected-output).

---

## How the agent works

Full design in [`docs/AGENT_DESIGN.md`](docs/AGENT_DESIGN.md). In short:

1. **Start** from the snapshot the operator handed over.
2. **Refuse to trust** a claim set built with no tracer, or with a window too
   short to have observed a periodic workload even once.
3. **Escalate while the answer is still moving.** If buying a longer window
   changed the claim set, the set has not converged, so keep buying while the
   budget allows. A claim set that is still changing is not safe to act on.
4. **Cross-check** every surviving claim against raw evidence.
5. **Stop**, recording *which* constraint ended the run - convergence, or
   budget.
6. **Self-verify** every generated artifact against the semantics of its own
   file format, repair deterministically, re-verify, and log each attempt.
7. **Stop at a human approval gate.** Never apply anything.

The hard part of an evidence-acquisition agent is not acquiring evidence, it
is stopping. Convergence-based stopping is what makes the result honest.

### The agent boundary

| The agent may decide | The agent may never decide |
| --- | --- |
| Which observation window to buy next | Any weight, gate, score, or CVE mapping |
| When to stop buying evidence | Which mitigation to recommend, or in what order |
| Which claims to cross-check | Whether to add or drop a plan step |
| When to hand off to a human | Whether to apply anything |

The invariant, pinned by `tests/test_agent_evidence.py`:

> **The report is a pure function of the final evidence set.**

Two runs ending on the same evidence produce identical reports - whichever
policy chose that evidence, and whether or not a model was involved. The blast
radius of a bad agent decision is bounded to *bought too much or too little
observation time*: a cost error, never a correctness error. This is why it is
safe to put an agent in a security tool at all.

The default policy needs **no API key**, so the headline result reproduces
offline. The optional LLM policy picks from the same tool menu; every invalid
choice falls back to the deterministic stop rule and is logged as a retry
rather than hidden.

---

## Run it

```bash
git clone https://github.com/RajvardhanPatil07/surface-warden.git
cd surface-warden
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

make demo      # baseline, then agent triage, then the comparison
make verify    # full test suite + frozen schema contract check
```

No host access, no root, no API key, no network after `pip install`. Under 30
seconds. Full guide, versions, runtime and cost: [`docs/REPRODUCE.md`](docs/REPRODUCE.md).

Individual entry points:

```bash
python warden.py baseline                  # static configuration checklist
python warden.py triage --budget 90000     # agent acquires evidence, then reports
python warden.py triage --budget 1000      # watch it stop early, and say why
python warden.py evaluate                  # all four arms, scored
python warden.py verify --report r.json    # re-verify a report's artifacts
```

The original single-shot scanner is unchanged: `python ksl.py scan`.

---

## Where the submission artifacts are

| Required item | Where |
| --- | --- |
| Solution code | `agent/`, `baseline/`, `evaluation/`, `warden.py` |
| Improvement changelog | [`docs/IMPROVEMENT_CHANGELOG.md`](docs/IMPROVEMENT_CHANGELOG.md) |
| Reproduction guide | [`docs/REPRODUCE.md`](docs/REPRODUCE.md) |
| Agent trajectories | `artifacts/runs/*/trajectory.jsonl` (regenerate with `make triage`) |
| Agent instructions | [`AGENTS.md`](AGENTS.md), section *The agent boundary* |
| Human checkpoint | `artifacts/runs/*/APPROVAL_REQUIRED.md` |
| Measured comparison | `artifacts/evaluation/comparison.md` (`make evaluate`) |

---

## What existed before this work, and what was added

The first commit in this repository is an unmodified import of
[`kernel-surface-ledger`](https://github.com/RajvardhanPatil07/kernel-surface-ledger)
(MIT, same author), which predates this work. See [`NOTICE`](NOTICE).

**Pre-existing:** `collector/` (read-only evidence collection), `engine/`
(reachability gating, workload attribution, CVE accounting, breakage-costed
set-cover planning), `artifacts/templates.py`, `explain/`, `web/`, `data/`
curated weights and CVE map, `report.schema.json`, and the tests covering
those.

**Added here:** `agent/` (evidence-acquisition agent, tool surface, stop rule,
artifact self-verification, trajectory writer), `baseline/` (static checklist
baseline), `evaluation/` (measurement harness), `fixtures/timeline-demo.json`
(replayable evidence timeline with held-out ground truth), `warden.py`,
`Makefile`, `docs/AGENT_DESIGN.md`, `docs/IMPROVEMENT_CHANGELOG.md`,
`docs/REPRODUCE.md`, and the four new test modules.

Exactly what changed:

```bash
git log --oneline pre-competition-baseline..HEAD
git diff --stat pre-competition-baseline..HEAD
```

`report.schema.json` was **not** modified - it is a frozen contract. All new
outputs live in separate paths (`artifacts/runs/`, `artifacts/evaluation/`).

---

## Coding-agent disclosure

The competition work in this repository was written with an AI coding agent
(Notion AI, Claude-based) driving the GitHub MCP server: it read the existing
engine, designed the evidence timeline and agent boundary, and authored the
code, tests and documentation in `agent/`, `baseline/`, `evaluation/` and
`docs/`. The author reviewed the design and is responsible for all of it.

Separately - and not to be confused with the above - the *shipped product*
contains its own agent, whose trajectories are the ones in
`artifacts/runs/*/trajectory.jsonl`. Those are generated by running
`make triage`, and record the product's evidence-acquisition decisions, not
the authoring process.

---

## Safety boundary

- **Read-only by design.** No code path loads or unloads a module, changes a
  sysctl, or applies a generated artifact. `warden.py --apply` refuses and
  explains why.
- **Human approval is a gate, not a suggestion.** Every run ends at
  `APPROVAL_REQUIRED.md`, with an artifact, a detection command and a revert
  for each step.
- **No tracer is not false certainty.** With tracing unavailable, syscall
  surface is never called orphaned merely because nothing was observed.
- **Missing access degrades, it does not crash.** Unreadable `/proc`, `/sys`
  or `/boot` sources are recorded in `meta.skipped` and the run continues.
- **No secrets, no private data.** All evidence is synthetic or from the
  author's own host. Model configuration is environment-only.

---

## Repository map

| Path | Purpose | Origin |
| --- | --- | --- |
| [`agent/`](agent) | Evidence tools, stop rule, verification, trajectories | added |
| [`baseline/`](baseline) | Static configuration checklist baseline | added |
| [`evaluation/`](evaluation) | Measurement harness and comparison output | added |
| [`fixtures/timeline-demo.json`](fixtures/timeline-demo.json) | Replayable evidence timeline + held-out ground truth | added |
| [`warden.py`](warden.py) | Competition CLI | added |
| [`engine/`](engine) | Deterministic reachability, attribution, planning | pre-existing |
| [`collector/`](collector) | Read-only Linux evidence collection | pre-existing |
| [`artifacts/templates.py`](artifacts/templates.py) | Deterministic artifact templates | pre-existing |
| [`explain/`](explain) | Optional narration, cached, non-scoring | pre-existing |
| [`web/`](web) | Dashboard ([live](https://kernel-surface-ledger.vercel.app/)) | pre-existing |
| [`data/`](data) | Human-curated weights and CVE map | pre-existing |

---

## Main failure mode

**The answer key only exists because this is a replayed timeline.** On a real
host nobody hands you ground truth - you get a change calendar, a maintenance
window and a soak period. The evidence timeline makes the *method* measurable;
it does not make the method omniscient. Ported to production, the agent's stop
rule still holds, but "converged" degrades from *provably correct* to *stopped
changing within the window I could afford*.

And the residual gap is structural: **a workload quieter than your longest
affordable observation window is still invisible.** A quarterly disaster-recovery
drill will look orphaned after a full day of tracing. The agent reports the
window it stopped on precisely so a human can weigh that against their own
change calendar - it does not pretend the gap is closed.

Secondary: the 900-second confidence floor is a curated constant chosen to
cover a standard metrics scrape cycle. A fleet with different periodicity
needs a different floor, and that number belongs in `data/`, curated by a
human, next to the weights.

---

## Hot take

**Most "AI for security" gets the boundary exactly backwards.** It puts the
model on the scoring - ranking findings, assigning severities, writing the
remediation plan - and leaves the human to gather evidence. That is inverted on
both halves.

Scoring is where you need determinism you can audit, diff and defend in a
post-incident review; "the model ranked it third" is not an answer a kernel
hardening tool is allowed to give. Meanwhile evidence gathering is where
judgment under cost actually lives: it is unbounded, it has a price, and it is
the part a human genuinely cannot brute-force.

So keep the model off the numbers, and let it decide what to go and find out.
The measurable win in this repository did not come from a smarter scorer. It
came from an agent that noticed its evidence was too thin to trust and went
and bought more - and then, harder, knew when to stop.

---

## License

MIT. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
