# NANOBYTE

> A million 2-millimeter SiC motes, deployed from a Starship-derived mothership, passively observe the afterglow of a LIBS laser ablating an asteroid — and a 24 KB Rust binary per mote decides in 400 microseconds whether the voxel it's attached to is made of platinum, water, or nothing worth bringing home.

Design doc: `~/.claude/plans/shotgun-nanobyte-sensor-swarm.plan.md`.

## Crates

| Crate | Target | Purpose |
|---|---|---|
| `nanobyte-core` | host + `riscv32imc-unknown-none-elf` | Shared types. `no_std` compatible. |
| `nanobyte-proto` | host | Wire format: 2-byte magic + seq + payload + CRC-16. |
| `nanobyte-mote` | `riscv32imc-unknown-none-elf` | Mote firmware. `no_std`, `panic = abort`, 32 KB flash budget. |
| `nanobyte-hive` | host (Linux) | Mothership flight software. `tokio`, f1–f10 handlers. |
| `nanobyte-sim` | host | Swarm digital twin — 1 M motes in a vacuum chamber. |
| `nanobyte-ground` | host | Mission-control UI. `axum` at `localhost:4000`. |
| `nanobyte-test` | host | Single staged test binary. P16: CI = Test Binary. |

## Build

```bash
# ground-side (everything except the mote firmware)
cargo check
cargo build --profile=diamond

# mote firmware (requires the cross toolchain)
rustup target add riscv32imc-unknown-none-elf
cargo build -p nanobyte-mote --target riscv32imc-unknown-none-elf --profile=diamond-edge

# staged CI
cargo run -p nanobyte-test
```

## Protocol stack

- **P26** Moonshot Frame — civilizational-stakes review before any design decision
- **P27** Diamond Rust Binary Architecture — speed-Diamond (ground) + size-Diamond (mote)
- **P28** Plasma Timing Discipline — every mote op has a plasma-regime budget, statically provable
- **P29** Dual-Laser Separation — LIBS laser ≠ interrogation laser, ever
- **P30** Swarm Observability Is Non-Negotiable — every mote emits a heartbeat on interrogation

## License

Unlicense. Public domain. Fork, strip, fly your own mission.
