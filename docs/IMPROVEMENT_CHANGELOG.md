# Improvement changelog

Each iteration below states what changed, why it was tried, the evidence it
is tied to, and what it measurably did. Regenerate every number with:

```bash
make evaluate   # writes artifacts/evaluation/comparison.{json,md}
```

The metric that decides whether an iteration was worth keeping:

- **False orphans** - live surface wrongly claimed removable. Each one is a
  potential outage.
- **Safe risk removed per unit of breakage cost** - hardening achieved
  without breaking anything.
- **Evidence cost (seconds)** - what the correctness was bought with.

---

## Baseline - static configuration checklist

`baseline/checklist.py`

The method mainstream kernel hardening checkers use: read the kernel config,
the module list and the sysctls, compare against a recommended set, emit
every deviation. Given the same snapshot and the same curated risk table as
every other arm, so the comparison is about method, not inputs.

**Result:** finds real issues, and claims live surface is removable, because
it has no usage model at all. Applying its recommendations wholesale breaks
working workloads.

**Why this is the fair baseline:** it is not a strawman. It is what the
existing tools in this space actually do, and it is the reason the ranked,
usage-aware approach exists.

---

## Iteration 1 - reachability gating and workload attribution

*Pre-competition work, in the repository before the challenge began. Listed
here for context, not as competition work. See `NOTICE`.*

The deterministic engine: separates present from unprivileged-reachable
surface, attributes surface to the workloads holding it open, and ranks
reversible mitigations by risk removed per unit of expected breakage.

**Result:** far fewer claims than the checklist, each attributable to a
named workload, each with an artifact, a detection command and a revert.

**Residual failure:** every claim is still only as good as the trace window
it was computed from. This is the failure the competition work addresses.

---

## Iteration 2 - name the real bottleneck: the observation window

`fixtures/timeline-demo.json`

The original README already conceded the weakness in one line: *"a quiet
nightly job can look unused at noon"*. It was documented and then left as
the operator's problem. Iteration 2 turns that sentence into a measurable
artifact: the same host recorded at four observation windows (0s, 60s, 900s,
86400s), with a held-out answer key established from the host's systemd
timers and scrape configuration.

What the timeline exposes at the 60-second window the operator hands over:

- `sc.perf_event_open` looks unused. It is used every 15 minutes by
  `node_exporter`.
- `sc.userfaultfd` looks unused. It is used once nightly by the 02:30 CRIU
  backup.

**Result:** two false orphans in the starting evidence. Both are recommended
for removal by the single-shot engine. Disabling either is a production
incident.

**Why this iteration mattered most:** without it there is nothing to
measure. A hardening tool with no answer key can only be argued about.

---

## Iteration 3 - make evidence acquisition an agent decision

`agent/tools.py`, `agent/policy.py`, `agent/loop.py`

The agent starts from the snapshot it was handed and decides, under an
explicit observation budget, whether to buy a longer window. The stop rule is
convergence-based: keep escalating while the claim set is still changing;
stop when more evidence stops changing the answer, or when the budget runs
out - and record which.

Crucially, the agent's authority is confined to *inputs*. It cannot touch a
weight, a score, an ordering or a plan step, and
`tests/test_agent_evidence.py` asserts the report is a pure function of the
final evidence set.

**Result:** false orphans fall as evidence is bought, and the agent converges
on the answer key. Evidence cost is reported alongside, so the trade-off is
visible rather than asserted.

**Deliberately kept honest:** the deterministic policy needs no API key, so
the headline result reproduces offline. The optional LLM policy chooses from
the same tool menu, and every invalid choice falls back and is logged as a
retry.

---

## Iteration 4 - two budgets instead of one, to show the price

`evaluation/harness.py`

A single agent arm would have hidden the cost. The harness scores the agent
at 1000 and 90000 observation-seconds so the curve is visible: the cheap
budget reaches the 15-minute window and clears the `perf_event_open` false
claim; only a full-day budget catches the nightly `userfaultfd` job.

**Result:** the improvement is a curve, not a single win. It also makes the
limitation explicit - catching a nightly job costs a night.

**Why this survived review:** it makes the solution look *worse* in the
cost column while making it far more credible. That trade is worth taking.

---

## Iteration 5 - self-verify every generated artifact

`agent/verify.py`

A config file that parses cleanly and does nothing is the worst possible
output, because it converts a security finding into false confidence. Each
artifact is now checked against the semantics of its own format - the
`modprobe` blacklist that needs an `install` override to actually work, the
systemd drop-in that is ignored without a `[Service]` header, the seccomp
profile missing an integer `errnoRet` - then repaired deterministically and
re-verified, with every attempt written to the trajectory.

**Result:** artifact defects are caught before a human is asked to look at
them, and anything unrepairable is reported with its reason rather than
quietly passed.

---

## Experiment removed: the LLM as planner

The obvious version of "add agentic AI" was to let a model choose the
mitigations and their order, using the engine only for scoring. It was built
and removed.

**Why it was removed:** it broke the property that makes this tool usable in
production. Plan ordering stopped being reproducible run to run, so two scans
of an unchanged host produced different recommendations, and the
determinism test in `tests/test_report.py` could not pass. Worse, there was
no way to tell a reviewer *why* a step was ranked third - the honest answer
was "a model said so", which is precisely the answer a kernel hardening tool
cannot give.

**What replaced it:** confining the agent to evidence acquisition. The agent
adds judgment where judgment is genuinely required and evidence is genuinely
incomplete, and stays out of the scoring path entirely. This is a smaller
claim about AI, and a much stronger tool.

**Also dropped:** container-based artifact verification. Running generated
artifacts against a live container would be stronger evidence, and would
make the result depend on Docker being present and on image pulls. Static
verification runs on a clean machine offline, which the reproducibility gate
values more than the marginal fidelity.
