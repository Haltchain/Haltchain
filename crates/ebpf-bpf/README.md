# haltchain-ebpf-bpf

eBPF programs for HaltChain syscall observability (enforcement maps still TODO).

## Build (Linux + nightly + BPF target)

```bash
rustup toolchain install nightly --component rust-src
rustup target add bpfel-unknown-none --toolchain nightly

cd crates/ebpf-bpf
cargo +nightly build --release --target=bpfel-unknown-none -Z build-std=core
```

The resulting object is copied to `$OUT_DIR/haltchain.o` by `build.rs`.

Userspace loader: `haltchain-ebpf` with `--features kernel` on Linux.

## Status

- Dependency: `aya-ebpf` (replaces removed `aya-bpf` crate)
- `check_policy()` is observability-only until map-driven deny is wired
