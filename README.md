# EVM Smart Contract Vanity Address Generator

This Rust helper brute-forces CREATE2 salts so you can land contracts (via `Create2Factory`) at vanity addresses. It consumes Hardhat artifacts (or any JSON artifact with `bytecode`), so you can point it at any compiled contract without rewriting init code by hand.

## Features

- Reads the factory address + artifact bytecode, then hashes like a real CREATE2 deploy would.
- Brute-forces salts with multi-threaded Rayon workers (defaults to all CPU cores).
- Optional checksum matching for case-sensitive vanity constraints.
- Single-shot mode (`--salt`) to predict the resulting address without brute force.

## Building

```bash
cargo build --release
```

The binary lives at `target/release/create2-vanity`. During development you can use `cargo run --release -- …`.

## Usage

```bash
cargo run --release -- \
  --factory 0xYourFactory \
  --artifact artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
  --prefix cafe \
  --suffix f00d \
  --checksum-match
```

Key flags (mirrors `--help`):

- `--factory <addr>` – deployed `Create2Factory` address (20-byte hex).
- `--artifact <path>` – Hardhat artifact JSON (default: `artifacts/contracts/SimpleStorage.sol/SimpleStorage.json`).
- `--salt <hex>` – deterministic mode; prints the resulting address and exits.
- `--prefix` / `--suffix` – lowercase hex constraints unless checksum mode is enabled.
- `--checksum-match` – apply prefix/suffix to the EIP-55 checksum form (case-sensitive). Slower but prettier.
- `--attempts <n>` – optional cap (0 = unlimited).
- `--threads <n>` – override Rayon worker count.

If neither `--prefix` nor `--suffix` is provided you must pass `--salt`.

## Performance tips

- Each constrained nibble multiplies difficulty by 16; checksum mode effectively doubles it per nibble. `bee…cafe` ≈ 1/16⁷, `cafe…babe` ≈ 1/16⁸, etc.
- Progress logs print every 10k attempts per worker. Redirect stdout for very long sessions.
- To split work across machines, run multiple instances with different RNG seeds (or swap in `SmallRng` with deterministic seeding).

## Example: predict a known salt

```bash
cargo run --release -- \
  --factory 0x3528225F82292570B366eB4da9727c3E1c9DfBdb \
  --artifact artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
  --salt 0xc261bc78b72af4a03d00448cc9230d0a861eef6a85ab9a0ef33e0432b868a524
```

Output shows the deterministic CREATE2 child address plus its checksum so you can verify deployments before broadcasting.

## Tweaking ideas

- Swap `StdRng` for `SmallRng` or a counter-based generator per thread.
- Precompute the packed `0xff || factory || salt || initHash` prefix so each iteration touches fewer bytes.
- Funnel status logging through a single channel/thread to avoid `println!` contention on huge runs.

PRs welcome if you add distributed search, checkpointing, or alternate front-ends!
