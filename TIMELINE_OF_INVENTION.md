<!-- Unlicense — cochranblock.org -->

# Timeline of Invention

*Dated, commit-level record of what was built, when, and why. Proves human-piloted AI development — not generated spaghetti.*

> Every entry below maps to real commits. Run `git log --oneline` to verify.

## How to Read This Document

Each entry follows this format:

- **Date**: When the work shipped (not when it was started)
- **What**: Concrete deliverable — binary, feature, fix, architecture change
- **Why**: Business or technical reason driving the decision
- **Commit**: Short hash(es) for traceability
- **AI Role**: What the AI did vs. what the human directed

This document exists because AI-assisted code has a trust problem. Anyone can generate 10,000 lines of spaghetti. This timeline proves that a human pilot directed every decision, verified every output, and shipped working software.

---

## Context

**NANOBYTE** is a deep-space asteroid-prospecting mission architecture: a Mothership + million-mote passive swarm for platinum and water mapping. Every binary on the mission is Rust. The mote firmware is `no_std` on RISC-V. Mission-class Rust, all the way down.

This repo is the software stack: shared types, wire protocol, mote firmware, mothership flight software, ground control, swarm simulator. Design doc: `~/.claude/plans/shotgun-nanobyte-sensor-swarm.plan.md`.

---

## Human Revelations — Invented Techniques

*Novel ideas that came from human insight, not AI suggestion. These are original contributions to the field.*

### The Gemini Audit (April 14, 2026)

**Invention:** Pitching a radical "Shotgun Nanobyte Sensor Swarm" architecture as a cross-disciplinary analogy — mapping AWS Lambda / Kubernetes / UDP / Webhook metaphors onto LIBS spectroscopy + MEMS smart dust — and then using that analogy layer as a *stress-test harness* for whether the physics actually holds.

**The Problem:** Deep-space mission architectures fail silently. An architect proposes something, the rocket engineers say "sure," the software engineers say "sure," nobody in the room has both hats, and the mission flies a design with a physics-level bug built in. Traditional design reviews use domain silos that can't catch cross-layer timing and metaphor failures.

**The Insight:** If you frame the physical architecture in software-engineering language, you *force* a clear mapping between the two. When the mapping leaks — when "Lambda cold-start" cannot actually boot inside a 10 μs plasma window — the leak is visible to anyone in the review regardless of discipline. The metaphor layer becomes a diff against reality. Brutal audit of the metaphor reveals brutal audit of the architecture.

**Named:** The Gemini Audit (for the architect whose first pass was caught by the frame)
**Commit:** *pending first Git commit*
**Origin:** Michael Cochran, pitching the architecture with deliberate Lambda/K8s/webhook analogies, then demanding a cross-hat review of whether the metaphors held.

### The Afterglow Shift (April 14, 2026)

**Invention:** Moving mote observation from the *in-plasma* window (μs, impossible for a 32 KB Rust BNN on a 25 MHz RISC-V core to service) to the *afterglow* window (ms — persistent thermal pulse, post-plasma spectral tail, magnetic anomaly, electrostatic charging). Same LIBS event, different physics the motes actually observe.

**The Problem:** The original architecture had the motes closing a read-inference-modulate loop inside the plasma emission window. LCD shutter response time (1–20 ms) is three orders of magnitude too slow. The spec was physically impossible — not a tuning problem, a physics problem.

**The Insight:** The motes do not need to participate in the primary LIBS measurement. The mothership's own spectrometer gets that. Motes add *spatial density of classification* by observing the secondary effects that linger after the plasma has dissipated. Lingering means ms to s of observation window, which is firmly inside the compute budget of a low-power embedded RISC-V running a 1-bit BNN.

**Named:** The Afterglow Shift
**Commit:** *pending first Git commit*
**Origin:** Michael Cochran, during the brutal-audit session; accepted without change after the timing budget was laid out.

### Dual-Laser Separation (April 14, 2026)

**Invention:** A mission-level protocol (P29) that prohibits any architecture in which the LIBS ablation laser and the mote-interrogation laser are the same beam. The LIBS laser does ablation at 1064 nm, pulsed. The interrogation laser polls and powers the motes at 1550 nm, continuous. Two jobs, two photon budgets, two timing regimes.

**The Problem:** Hardware cost pressure on space missions always argues for consolidation. "Can we use one laser for both?" is the first question every program manager asks. The answer, for this architecture, is always no — because merging the two collapses the timing budget and eliminates the ability to use Starlink ISL silicon for the interrogation head.

**The Insight:** Codify the separation as a named protocol so the question is not debated again in future design reviews. Any proposal to re-merge the beams is rejected at the protocol level, not the engineering level. This is the same pattern as P12 banned words — prevent a class of bad decisions by naming the class.

**Named:** Dual-Laser Separation (P29)
**Commit:** *pending first Git commit*
**Origin:** Michael Cochran, codifying the separation after the Afterglow Shift made the timing budget viable.

### SwarmCtl Is tmuxisfree For Space (April 14, 2026)

**Invention:** Lifting the `tmuxisfree` fleet-orchestration model — dispatch / backlog / peek / drain, compressed tf* tokens, a C2 hub pane controlling many worker panes — and applying it to a million-mote asteroid swarm with only the identifiers changed. `sc0` = swarm status. `scp` = push science target to a sector backlog. `scdr` = drain all targets against the LIBS thermal budget.

**The Problem:** Space missions design bespoke command-and-control systems from scratch. Those systems have no ground heritage — operators learn them during integration testing, which is exactly when operator-error manifests. A proven ops paradigm that already runs 28+ AI agents in a production tmux fleet is a heritage system. Re-using it costs nothing and de-risks the operator interface.

**The Insight:** Fleet orchestration is fleet orchestration. The fact that the workers are AI agents in a terminal or dust motes on an asteroid does not change the mental model. Push, pop, drain, dispatch, peek, unblock — the primitives are universal. Prove them on terminals; deploy them in space.

**Named:** SwarmCtl = tmuxisfree-for-space
**Commit:** *pending first Git commit*
**Origin:** Michael Cochran's tmuxisfree pattern; application to asteroid swarm during the NANOBYTE plan write-up.

---

## Entries

<!-- Add entries in reverse chronological order. Template:

### YYYY-MM-DD — [Short Title]

**What:** [Concrete deliverable]
**Why:** [Business/technical driver]
**Commit:** `abc1234`
**AI Role:** [What AI generated vs. what human directed/verified]
**Proof:** [Link to artifact, screenshot, or test output]

-->

### 2026-04-14 — Initial Scaffold + Plan

**What:** Workspace repository at `~/dev/nanobyte/` with seven-crate structure: `nanobyte-core` (no_std shared types), `nanobyte-proto` (wire format), `nanobyte-mote` (rv32imc firmware), `nanobyte-hive` (mothership flight software), `nanobyte-sim` (swarm digital twin), `nanobyte-ground` (mission-control UI), `nanobyte-test` (staged CI binary). Workspace Cargo.toml with P27 Diamond profiles (speed + edge variants). Unlicense header on every file. First wire types: `MoteId`, `VoxelAddr`, `Classification`, `MoteFrame`, `AddressBlock`. Roundtrip + bounds tests on `Classification`. Design doc at `~/.claude/plans/shotgun-nanobyte-sensor-swarm.plan.md` locks the architecture, flight program, and risk register. TIMELINE_OF_INVENTION.md + PROOF_OF_ARTIFACTS.md published per cochranblock provenance convention.
**Why:** A mission needs a repository before it has a spacecraft. Starting with a disciplined workspace layout prevents the usual embedded-vs-ground code-organization drift. Writing the plan first, the docs second, the code third is the inverse of how most space programs run and is cheaper to correct.
**Commit:** *pending — first commit will tag `[P26][P27][P28][P29][P30][Block 0.0]`*
**AI Role:** Claude Opus 4.6 performed the Gemini-architecture audit, drafted the plan document, authored the initial Cargo workspace, and drafted these provenance files. Human (Michael Cochran) rejected the Gemini architecture over a physics-level bug, directed the corrections, invented the three named techniques above, and confirmed the crate-name namespace with crates.io before the first write.
**Proof:** `~/dev/nanobyte/Cargo.toml` exists, lists seven workspace members, defines `diamond` + `diamond-edge` profiles. `~/.claude/plans/shotgun-nanobyte-sensor-swarm.plan.md` exists at ~12 KB, 10 sections. All 9 crate names confirmed available via `curl crates.io/api/v1/crates/<name>` returning 404 for each.
