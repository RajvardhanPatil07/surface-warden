# Solution video - beat sheet (5:00 max)

Record a terminal with a readable font, plus the two Markdown outputs. No
slides needed beyond the first ten seconds. Every number spoken must come
from a command visible on screen.

---

## 0:00-0:35 - The problem, and who has it

> "This is for the person who owns a fleet of Linux hosts and has been handed
> a kernel hardening checklist. Their bottleneck is not finding issues - a
> config checker finds hundreds. It is deciding which ones are safe to apply
> without taking down production."

> "Every tool in this space answers 'is this setting present'. None answers
> 'will removing it break something'. That is the question that actually
> blocks the change ticket."

---

## 0:35-1:20 - The baseline, and exactly how it fails

```bash
python warden.py baseline
```

> "Here is the standard method: static configuration checklist. Same host,
> same curated risk table the advanced solution uses. It finds real issues.
> Note the last line - usage measured: no."

> "So it recommends removing surface that a live workload depends on. And
> the interesting part is that the smart version of this tool fails too, for
> a subtler reason."

Show `fixtures/timeline-demo.json` briefly.

> "`used` means observed during the trace window. The snapshot the operator
> hands over is 60 seconds at midday. `perf_event_open` looks unused - it is
> used every 15 minutes by node_exporter. `userfaultfd` looks unused - it is
> used once nightly by the 02:30 backup. Two false claims, both outages."

---

## 1:20-2:50 - One realistic end-to-end run

```bash
python warden.py triage --budget 90000
```

Narrate as it runs, then open `artifacts/runs/latest/trajectory.jsonl`.

> "The agent starts on the 60-second window. Sixty seconds is below the floor
> for observing a periodic job even once, so it buys 15 minutes. That
> withdraws the `perf_event_open` claim - node_exporter shows up."

> "The claim set just changed, which means it has not converged, so it buys a
> full day. That withdraws `userfaultfd` - there is the nightly backup."

> "Now the set is stable, so it cross-checks each surviving claim against raw
> evidence, and stops. Every step is in the trajectory with the reason it was
> taken."

Show a verification record, then `APPROVAL_REQUIRED.md`.

> "Each generated artifact gets checked against its own format - here, a
> modprobe blacklist without the install override, which would not actually
> stop the module loading. Repaired and re-verified, both attempts logged."

> "And it ends here: pending human approval. There is no code path in this
> repository that applies a kernel change. `--apply` refuses."

---

## 2:50-3:50 - The comparison

```bash
python warden.py evaluate
```

Open `artifacts/evaluation/comparison.md`.

> "Four arms, same host, same weights. Read the false-orphan row: the
> checklist, then the single-shot engine, then the agent at a small budget,
> then at a full-day budget - down to zero, matching a held-out answer key
> the agent cannot see."

> "Now read the evidence-cost row, because this is the honest part: zero,
> zero, 900 seconds, 87300 seconds. Correctness was bought. The last column
> of the improvement is a night of observation."

> "The bottom line is safe risk removed per unit of expected breakage - the
> single number for 'hardened the host without causing an outage'."

---

## 3:50-4:30 - Changelog: the change that mattered, and the one removed

> "Biggest-contributing change: building the evidence timeline with a
> held-out answer key. Before it, the weakness was one honest sentence in the
> README. After it, it is a number that moves."

> "The experiment I removed: letting the model pick the mitigations and their
> order. It worked, and it broke reproducibility - two scans of an unchanged
> host gave different plans, and the only available explanation for a ranking
> was 'a model said so'. I confined the agent to evidence acquisition
> instead. Smaller claim about AI, much stronger tool."

---

## 4:30-5:00 - Failure mode and hot take

> "Main failure mode: the answer key exists because this is a replayed
> timeline. On a real host, nobody hands you ground truth - you get a change
> calendar and a soak period. This measures the method, it does not make the
> method omniscient. And a workload quieter than your longest affordable
> window is still invisible."

> "Hot take: most 'AI for security' gets the boundary backwards. It puts the
> model on the scoring and lets the human gather evidence. That is exactly
> inverted. Scoring is where you need determinism you can audit; evidence
> gathering is where judgment under cost actually lives. Keep the model off
> the numbers and let it decide what to go and find out."

---

## Checklist before uploading

- [ ] Under 5:00
- [ ] Problem, intended user and bottleneck stated in the first 40 seconds
- [ ] Baseline shown running, not described
- [ ] One complete end-to-end execution, unedited
- [ ] Comparison table on screen with the evidence-cost row visible
- [ ] Biggest-contributing change and the removed experiment both named
- [ ] Failure mode stated before the hot take
- [ ] Coding-agent use disclosed on screen or in the description
