# EVM Vanity Toolkit

Two binaries live in this workspace:

- **`create2-vanity`** – brute-forces CREATE2 salts so contracts deployed via `Create2Factory` (or the universal CREATE2 deployer) can land at vanity addresses. It reads Hardhat artifacts, ABI-encodes constructor args for you, and mirrors the exact hashing that a chain performs before CREATE2 deployments.
- **`vanity_eoa`** – brute-forces externally-owned account (EOA) private keys whose addresses match a desired prefix/suffix. It reuses the same deterministic scheduling, checkpoint/resume flow, and exposes progress stats that dashboards can scrape.

Both binaries are CPU-bound Rust executables built on Rayon for multi-threading and TinyKeccak for hashing.

## Installation

```bash
cargo build --release
```

`target/release/create2-vanity` is the default binary. Use `cargo run --release -- …` for CREATE2 searches or add `--bin vanity_eoa` to run the EOA searcher during development.

## Quick start

### CREATE2 vanity search

```bash
cargo run --release -- \
  --factory 0xYourFactory \
  --artifact artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
  --prefix cafe --suffix f00d \
  --checksum-match \
  --checkpoint salts-checkpoint.json
```

### EOA vanity keys

```bash
cargo run --release --bin vanity_eoa -- \
  --prefix cafe --suffix f00d \
  --checksum-match \
  --checkpoint vanity-checkpoint.json \
  --stats-interval 10 --stats-json
```

## Repository layout

- `contracts/` – Solidity sources such as `Create2Factory.sol` and `SimpleStorage.sol`.
- `scripts/` – Helper utilities (currently the CREATE2 calldata builder for the universal deployer).
- `src/` – The main Rust crate that brute-forces CREATE2 salts and EOA keys.
- `results/` – Default home for result/checkpoint JSON (ignored by git except for `.gitkeep`).

## CLI reference

### `create2-vanity`

- `--factory <addr>` – deployed `Create2Factory` address (20-byte hex).
- `--artifact <path>` – Hardhat artifact JSON with `bytecode` + ABI (default: `artifacts/contracts/SimpleStorage.sol/SimpleStorage.json`).
- `--bytecode <hex>` – bypass the artifact and hash this init code directly.
- `--constructor-args <csv>` – parse/encode constructor args via the artifact ABI before hashing (comma separated). Order must match the constructor signature.
- `--salt <hex>` – deterministic one-off mode; prints the resulting address/checksum and exits.
- `--prefix`, `--suffix` – lowercase hex constraints unless checksum mode is enabled.
- `--checksum-match` – apply prefix/suffix to the EIP-55 checksum (case-sensitive). Prettier, but slower per nibble.
- `--attempts <n>` – optional attempt cap (0 = unlimited).
- `--threads <n>` – override Rayon worker count (defaults to CPU cores).
- `--seed <u64>` – deterministic RNG seed so you can shard across machines or resume later.
- `--checkpoint <path>` / `--checkpoint-interval <n>` – persist the next attempt counter + config hash to JSON every N attempts.
- `--resume <path>` – restart exactly where a checkpoint left off (enforces matching config + seed).
- `--output <path>` – append successful hits to this JSON file (defaults to `results/salt.json`).

### `vanity_eoa`

- `--prefix`, `--suffix`, `--checksum-match`, `--attempts`, `--threads`, `--seed` – same semantics as `create2-vanity`.
- `--checkpoint <path>` / `--resume <path>` / `--checkpoint-interval <n>` – identical checkpoint/resume flow (stored as `next_attempt`, `base_seed`, `config_hash`).
- `--output <file>` – defaults to `results/vanity-eoa.json`. Each entry includes the private key, public key (uncompressed SEC1), address, checksum, attempts, and search parameters.
- `--mnemonic` – generate BIP-39 mnemonics and derive the vanity address via HD wallets instead of emitting standalone private keys.
- `--hd-path <path>` – derivation path used when `--mnemonic` is set (default: `m/44'/60'/0'/0/0`).
- `--derive-attempt <n>` – with `--seed`, recreate the key/mnemonic for a specific attempt index and exit (no brute force run).
- `--stats-interval <seconds>` – emit periodic progress (attempts checked + attempts/s). Set to 0 to disable.
- `--stats-json` – emit stats as `STATS {"attempts":…}` JSON instead of human text, perfect for dashboards.

## Deterministic search & seeds

Both binaries derive work items from `(seed, attempt_id)`. CREATE2 salts hash the tuple into a 32-byte salt; the EOA searcher hashes it into private key material (discarding invalid keys). This guarantees:

- Reproducibility – using the same seed and attempt range replays the exact salts/keys.
- Safe sharding – give each machine a unique seed to avoid overlapping attempts.
- Seamless resume – checkpoints store the next attempt ID, so resuming never re-processes old work.

If you omit `--seed`, the CLI draws a random seed and prints it so you can reuse it later.

## Checkpoint & resume

- Pass `--checkpoint path.json` to periodically flush `{version,next_attempt,base_seed,config_hash}`.
- Use `--resume path.json` (optionally alongside `--checkpoint path.json` to keep updating the same file) to continue from that attempt ID.
- `config_hash` covers every search parameter + seed, so mismatched resumes are rejected.
- On exit—whether a hit is found or the attempt limit is reached—the CLIs force one last checkpoint write so the file always reflects the next attempt to try.
- Need to inspect a past attempt without re-running the search? Pass `--seed <base_seed> --derive-attempt <id>` (optionally with `--mnemonic/--hd-path`) to recreate the exact key/mnemonic for that attempt and print it immediately.

## Result exports

Both binaries append hits under `results/` (`results/salt.json` or `results/vanity-eoa.json`). Entries capture:

- Inputs: factory, artifact path, constructor args, prefix/suffix, checksum mode, seed.
- Outputs: salt, contract address, checksum, init-code hash (CREATE2) **or** private key, public key, optional mnemonic + derivation path, address, checksum (EOA).
- Search metadata: attempts taken, attempt cap, bytecode source, stats mode, etc.

Use `--output` to target a different path. Existing files are interpreted as JSON arrays, so you can accumulate multiple hits or merge across runs.

## Performance tips

- Each constrained nibble multiplies difficulty by 16; checksum mode roughly doubles the cost per nibble. `bee…cafe` ≈ 1/16⁷, `cafe…babe` ≈ 1/16⁸, etc.
- Progress logs now emit every 10k attempts from worker 0 (in addition to optional stats). Redirect stdout for very long sessions.
- Lowering `--checkpoint-interval` gives more frequent resume points but spends more time writing JSON; tune to match your environment.

## Constructor encoding & calldata

When you pass `--constructor-args`, `create2-vanity` loads the Hardhat artifact ABI, tokenizes each value, ABI-encodes them, then appends the payload to the bytecode before hashing. This guarantees the CREATE2 address derived here matches the address produced when you later deploy.

Need calldata for the universal CREATE2 deployer (`0x4e59…4956C` on many networks)? Use the companion script:

```bash
npm exec tsx scripts/build-create2-calldata.ts \
  --salt 0xSaltFromVanityTool \
  --artifact artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
  --constructor-args 0xOwnerAddress \
  --out calldata.txt

cast send 0x4e59b44847B379578588920cA78FbF26c0B4956C \
  --value 0 \
  --data $(cat calldata.txt) \
  --rpc-url <rpc>
```

### Keep constructor args in sync

- Use the exact same arguments for the CREATE2 search (`create2-vanity --constructor-args …`) and the calldata builder so the init-code hash stays consistent.
- When verifying deployments on explorers (Hardhat example):
  ```bash
  npm exec hardhat verify -- --network <net> <deployed-address> "0xOwnerAddress"
  ```
  Provide the same constructor values you encoded above (wrap multiple args in a JSON array).

## Bonus: deploying through the universal CREATE2 factory

The singleton CREATE2 deployer accepts calldata encoded as `salt (32 bytes) || init_code`. By pairing a salt from `create2-vanity` with calldata produced by `scripts/build-create2-calldata.ts`, you can deterministically land vanity contracts even before your own `Create2Factory` is deployed. Once your factory is live, you can call its ABI directly using the same salt + init code to produce the identical vanity address.

## Tweaking ideas

- Add a coordinator that hands out `(seed, attempt window)` slices across a fleet.
- Experiment with SIMD/GPU Keccak implementations once CPU-side overhead is minimized.
- Extend the stats output with attempts-per-second histograms or Prometheus exporters for richer observability.

PRs welcome!
