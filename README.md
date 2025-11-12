# EVM Smart Contract Vanity Address Generator

This Rust helper brute-forces CREATE2 salts so you can land contracts (via `Create2Factory` or the universal CREATE2 deployer) at vanity addresses. It consumes Hardhat artifacts (or any JSON artifact with `bytecode`) and can also take a raw bytecode hex blob, so you can point it at any compiled contract without rewriting init code by hand.

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
- `--bytecode <hex>` – override the artifact and hash this raw init code (useful when you already appended constructor args).
- `--constructor-args <csv>` – supply comma-separated constructor arguments (parsed using the artifact ABI and encoded automatically).
- `--salt <hex>` – deterministic mode; prints the resulting address and exits.
- `--prefix` / `--suffix` – lowercase hex constraints unless checksum mode is enabled.
- `--checksum-match` – apply prefix/suffix to the EIP-55 checksum form (case-sensitive). Slower but prettier.
- `--attempts <n>` – optional cap (0 = unlimited).
- `--threads <n>` – override Rayon worker count.
- `--seed <u64>` – deterministic RNG seed so you can resume a run or shard work across machines. Defaults to OS randomness.
- `--checkpoint <path>` – periodically write a JSON checkpoint with the next attempt counter + config hash.
- `--resume <path>` – restart from a previously saved checkpoint (enforces matching config + seed).
- `--checkpoint-interval <n>` – attempts between checkpoint flushes (default: 100k).

If neither `--prefix` nor `--suffix` is provided you must pass `--salt`.

Constructor encoding: the tool reads the artifact ABI and, if you pass `--constructor-args`, ABI-encodes those values (comma-separated) before hashing the init code. Example for a single `address` parameter: `--constructor-args 0x1234...dead`. The arguments must appear in the same order as the constructor inputs.

## Performance tips

- Each constrained nibble multiplies difficulty by 16; checksum mode effectively doubles it per nibble. `bee…cafe` ≈ 1/16⁷, `cafe…babe` ≈ 1/16⁸, etc.
- Progress logs now emit every 10k attempts from worker 0 to minimize stdout contention. Redirect stdout for very long sessions.
- Salts are derived deterministically from `(seed, attempt_index)`, so two runs only overlap if they intentionally share both values. Give each machine a unique `--seed` to split work safely.

## Checkpoint & resume

- Pass `--checkpoint checkpoint.json` to write the current attempt counter every `--checkpoint-interval` attempts (defaults to 100k). The file stores the base seed, config hash, and the next attempt to try.
- Use `--resume checkpoint.json` (optionally along with `--checkpoint` to keep updating the same file) to continue exactly where you left off. The CLI verifies the hash of all search parameters plus the seed to prevent mismatched resumes.
- Because salts depend only on `(seed, attempt)`, resuming does not re-check previously tested salts—execution jumps straight to the stored attempt ID.

## Example: predict a known salt

```bash
cargo run --release -- \
  --factory 0x3528225F82292570B366eB4da9727c3E1c9DfBdb \
  --artifact artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
  --salt 0xc261bc78b72af4a03d00448cc9230d0a861eef6a85ab9a0ef33e0432b868a524
```

Output shows the deterministic CREATE2 child address plus its checksum so you can verify deployments before broadcasting.

## Tweaking ideas

- Add a lightweight coordinator/worker protocol so you can dole out seed windows automatically across a fleet.
- Experiment with SIMD/GPU Keccak implementations once CPU-side overhead is squeezed out.
- Surface live stats (attempts/s, ETA per nibble, etc.) through a structured logging or metrics endpoint for richer monitoring.

PRs welcome if you add distributed search, checkpointing, or alternate front-ends!

## Bonus: deploying through the universal CREATE2 factory

Many networks ship the singleton CREATE2 deployer at `0x4e59b44847B379578588920cA78FbF26c0B4956C`. It has no ABI—just send calldata encoded as `salt (32 bytes) || init_code`. You can pipe the artifact + salt that this tool found into `scripts/build-create2-calldata.ts`:

```bash
npm exec tsx scripts/build-create2-calldata.ts \
  --salt 0xYourSaltFoundByVanityTool \
  --artifact artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
  --constructor-args 0xOwnerAddress \
  --out calldata.txt
```

That writes the calldata blob to `calldata.txt` (and displays it in stdout). Broadcast it with your favorite sender, e.g.:

```bash
cast send 0x4e59b44847B379578588920cA78FbF26c0B4956C \
  --value 0 \
  --data $(cat calldata.txt) \
  --rpc-url <rpc>
```

The singleton will CREATE2-deploy the provided init code using the exact salt you searched for, yielding the deterministic vanity address. Once your own `Create2Factory` is live you can call its ABI directly, but the universal deployer is perfect for bootstrapping the very first factory or any one-off vanity contract.

### Keep constructor args in sync

- Pass identical arguments to both the vanity search (`create2-vanity --constructor-args …`) and the calldata builder (`scripts/build-create2-calldata.ts --constructor-args …`) so the init-code hash stays consistent.
- When verifying on explorers (Hardhat example):  
  ```bash
  npm exec hardhat verify -- --network <net> <deployed-address> "0xOwnerAddress"
  ```  
  Replace the address string with the same constructor value you encoded above (or wrap multiple args in a JSON array).
