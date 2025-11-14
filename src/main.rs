use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ethabi::token::{LenientTokenizer, Tokenizer};
use ethabi::Contract;
use hex::FromHex;
use rand::Rng;
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use tiny_keccak::{Hasher, Keccak};

#[derive(Parser, Debug)]
#[command(name = "create2-vanity")]
#[command(about = "Brute force CREATE2 salts for vanity contract addresses", long_about = None)]
struct Args {
    /// Deployed Create2Factory address (20-byte hex)
    #[arg(long)]
    factory: String,

    /// Path to Hardhat artifact JSON (must include `bytecode`)
    #[arg(
        long,
        default_value = "artifacts/contracts/SimpleStorage.sol/SimpleStorage.json"
    )]
    artifact: PathBuf,

    /// Optional raw bytecode to use instead of reading from the artifact
    #[arg(long)]
    bytecode: Option<String>,

    /// Optional comma-separated constructor arguments (parsed against the artifact ABI)
    #[arg(long = "constructor-args", value_delimiter = ',', num_args = 0..)]
    constructor_args: Option<Vec<String>>,

    /// Optional explicit salt. Prints the resulting address and exits.
    #[arg(long)]
    salt: Option<String>,

    /// Match prefix/suffix against the EIP-55 checksum address (case-sensitive).
    #[arg(long)]
    checksum_match: bool,

    /// Require the resulting address to start with this hex (no 0x)
    #[arg(long)]
    prefix: Option<String>,

    /// Require the resulting address to end with this hex (no 0x)
    #[arg(long)]
    suffix: Option<String>,

    /// Maximum attempts before giving up (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    attempts: u64,

    /// Number of worker threads (defaults to CPU cores)
    #[arg(long)]
    threads: Option<usize>,

    /// Optional deterministic RNG seed (u64). Enables reproducible or sharded searches.
    #[arg(long)]
    seed: Option<u64>,

    /// Path to write periodic checkpoint JSON (stores the next attempt + config hash).
    #[arg(long)]
    checkpoint: Option<PathBuf>,

    /// Resume search from an existing checkpoint file.
    #[arg(long)]
    resume: Option<PathBuf>,

    /// Attempts between checkpoint flushes (only used with --checkpoint).
    #[arg(long, default_value_t = 100_000)]
    checkpoint_interval: u64,

    /// Optional path to write the result (JSON) when a matching salt is found.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Artifact {
    bytecode: String,
    abi: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct CheckpointFile {
    version: u32,
    next_attempt: u64,
    base_seed: u64,
    config_hash: String,
}

#[derive(Serialize)]
struct SearchResult {
    factory: String,
    salt: String,
    address: String,
    checksum: String,
    init_hash: String,
    attempts: u64,
    attempts_limit: Option<u64>,
    seed: u64,
    prefix: Option<String>,
    suffix: Option<String>,
    checksum_match: bool,
    artifact: String,
    bytecode_source: String,
    constructor_args: Option<Vec<String>>,
}

const ATTEMPT_BATCH: u64 = 2048;
const PROGRESS_INTERVAL: u64 = 10_000;

struct CheckpointWriter {
    path: PathBuf,
    config_hash: String,
    base_seed: u64,
    interval: u64,
    next_flush: AtomicU64,
    lock: Mutex<()>,
}

impl CheckpointWriter {
    fn new(path: PathBuf, config_hash: String, base_seed: u64, interval: u64) -> Self {
        Self {
            path,
            config_hash,
            base_seed,
            interval: interval.max(1),
            next_flush: AtomicU64::new(0),
            lock: Mutex::new(()),
        }
    }

    fn maybe_write(&self, attempts: u64) {
        let target = self.next_flush.load(Ordering::Relaxed);
        if attempts < target {
            return;
        }
        if let Ok(_guard) = self.lock.try_lock() {
            let target = self.next_flush.load(Ordering::Relaxed);
            if attempts < target {
                return;
            }
            if let Err(err) = self.write_file(attempts) {
                eprintln!(
                    "Failed to write checkpoint {}: {err:?}",
                    self.path.display()
                );
            } else {
                let next = attempts.saturating_add(self.interval);
                self.next_flush.store(next, Ordering::Relaxed);
            }
        }
    }

    fn force_write(&self, attempts: u64) -> Result<()> {
        let _guard = self.lock.lock().expect("checkpoint mutex poisoned");
        self.write_file(attempts)?;
        let next = attempts.saturating_add(self.interval);
        self.next_flush.store(next, Ordering::Relaxed);
        Ok(())
    }

    fn write_file(&self, attempts: u64) -> Result<()> {
        let payload = CheckpointFile {
            version: 1,
            next_attempt: attempts,
            base_seed: self.base_seed,
            config_hash: self.config_hash.clone(),
        };
        save_checkpoint_file(&self.path, &payload)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let artifact_path_str = args.artifact.display().to_string();
    let bytecode_source = match (args.bytecode.is_some(), args.constructor_args.as_ref()) {
        (true, Some(_)) => "inline-bytecode+constructor-args".to_string(),
        (true, None) => "inline-bytecode".to_string(),
        (false, Some(_)) => "artifact+constructor-args".to_string(),
        (false, None) => "artifact".to_string(),
    };
    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("results/salt.json"));

    let factory = parse_address(&args.factory)?;
    let need_artifact = args.bytecode.is_none() || args.constructor_args.is_some();
    let artifact = if need_artifact {
        Some(load_artifact(&args.artifact)?)
    } else {
        None
    };
    let mut bytecode_hex = if let Some(custom) = &args.bytecode {
        custom.clone()
    } else {
        artifact
            .as_ref()
            .map(|a| a.bytecode.clone())
            .expect("artifact must be loaded when --bytecode is not provided")
    };
    if let Some(constructor_args) = &args.constructor_args {
        let artifact = artifact
            .as_ref()
            .ok_or_else(|| anyhow!("--constructor-args requires an artifact with ABI"))?;
        bytecode_hex = encode_constructor(bytecode_hex, artifact, constructor_args)?;
    }
    let bytecode = parse_hex_bytes(&bytecode_hex)?.into_boxed_slice();
    if bytecode.is_empty() {
        return Err(anyhow!("Bytecode payload is empty"));
    }

    let init_hash = keccak(&bytecode);

    if let Some(salt_hex) = &args.salt {
        let salt = parse_salt(salt_hex)?;
        let address = compute_address(&factory, &salt, &init_hash);
        println!("Factory   : {}", format_hex(&factory));
        println!("Salt      : {}", format_hex(&salt));
        println!("Init hash : {}", format_hex(&init_hash));
        println!("Address   : {}", format_hex(&address));
        println!("Checksum  : {}", checksum_address(&address));
        return Ok(());
    }

    let prefix = if args.checksum_match {
        args.prefix.clone()
    } else {
        args.prefix.as_deref().map(|s| s.to_ascii_lowercase())
    };
    let suffix = if args.checksum_match {
        args.suffix.clone()
    } else {
        args.suffix.as_deref().map(|s| s.to_ascii_lowercase())
    };
    if prefix.is_none() && suffix.is_none() {
        return Err(anyhow!("Provide --prefix/--suffix or --salt"));
    }

    let max_attempts = if args.attempts == 0 {
        u64::MAX
    } else {
        args.attempts
    };

    let threads = args
        .threads
        .or_else(|| std::thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(1)
        .max(1);
    let checksum_mode = args.checksum_match;

    let mut base_seed = args.seed.unwrap_or_else(|| rand::thread_rng().gen());
    let mut resume_attempt = 0u64;
    let resume_checkpoint = if let Some(path) = args.resume.as_ref() {
        Some((
            path.clone(),
            load_checkpoint_file(path)
                .with_context(|| format!("Failed to load checkpoint at {}", path.display()))?,
        ))
    } else {
        None
    };

    if let Some((_, checkpoint)) = &resume_checkpoint {
        if let Some(seed) = args.seed {
            if seed != checkpoint.base_seed {
                return Err(anyhow!(
                    "Checkpoint base seed ({}) does not match --seed ({})",
                    checkpoint.base_seed,
                    seed
                ));
            }
        }
        base_seed = checkpoint.base_seed;
        resume_attempt = checkpoint.next_attempt;
    }

    let config_hash = hex::encode(config_fingerprint(
        base_seed,
        &factory,
        &init_hash,
        &prefix,
        &suffix,
        checksum_mode,
    ));

    if let Some((_, checkpoint)) = &resume_checkpoint {
        if checkpoint.config_hash != config_hash {
            return Err(anyhow!(
                "Checkpoint was created for different search parameters."
            ));
        }
    }

    if resume_attempt >= max_attempts {
        println!("Checkpoint already exhausted the requested attempt budget.");
        return Ok(());
    }

    println!("Searching for vanity salt...");
    println!("Factory   : {}", format_hex(&factory));
    if args.bytecode.is_some() && args.constructor_args.is_none() {
        println!("Bytecode  : provided via --bytecode");
    } else {
        println!("Artifact  : {}", args.artifact.display());
    }
    println!("Init hash : {}", format_hex(&init_hash));
    if let Some(p) = &prefix {
        println!("Prefix    : {}", p);
    }
    if let Some(s) = &suffix {
        println!("Suffix    : {}", s);
    }
    if checksum_mode {
        println!("Matching  : checksum (case-sensitive)");
    } else {
        println!("Matching  : lowercase hex");
    }
    let max_display = if max_attempts == u64::MAX {
        "∞".to_string()
    } else {
        max_attempts.to_string()
    };
    println!("Max tries : {}", max_display);
    println!("Threads   : {}", threads);
    match (&resume_checkpoint, args.seed) {
        (Some(_), _) => println!("RNG seed  : {} (from checkpoint)", base_seed),
        (None, Some(seed)) => println!("RNG seed  : {} (user supplied)", seed),
        (None, None) => println!("RNG seed  : {} (randomized)", base_seed),
    }
    if resume_attempt > 0 {
        println!("Start at  : attempt {}", resume_attempt);
    }
    if let Some((path, _)) = &resume_checkpoint {
        println!("Resume    : {}", path.display());
    }
    if let Some(path) = &args.checkpoint {
        println!(
            "Checkpoint : {} (every {} attempts)",
            path.display(),
            args.checkpoint_interval.max(1)
        );
    }

    let checkpoint_writer = if let Some(path) = args.checkpoint.clone() {
        if args.checkpoint_interval == 0 {
            return Err(anyhow!("--checkpoint-interval must be greater than 0"));
        }
        let writer = Arc::new(CheckpointWriter::new(
            path,
            config_hash.clone(),
            base_seed,
            args.checkpoint_interval,
        ));
        writer.force_write(resume_attempt)?;
        Some(writer)
    } else {
        None
    };

    let start = Instant::now();
    let scheduler = Arc::new(AtomicU64::new(resume_attempt));
    let attempts_done = Arc::new(AtomicU64::new(resume_attempt));
    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(Mutex::new(None));

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .context("Failed to build rayon thread pool")?;

    pool.install(|| {
        rayon::scope(|s| {
            for worker_idx in 0..threads {
                let scheduler = Arc::clone(&scheduler);
                let attempts_done = Arc::clone(&attempts_done);
                let found = Arc::clone(&found);
                let result = Arc::clone(&result);
                let factory = factory;
                let init_hash = init_hash;
                let prefix = prefix.clone();
                let suffix = suffix.clone();
                let checksum_mode = checksum_mode;
                let checkpoint = checkpoint_writer.clone();

                s.spawn(move |_| {
                    let mut data = build_data_template(&factory, &init_hash);
                    let mut stop = false;

                    while !stop {
                        if found.load(Ordering::Acquire) {
                            break;
                        }

                        let start = scheduler.fetch_add(ATTEMPT_BATCH, Ordering::Relaxed);
                        if start >= max_attempts {
                            break;
                        }

                        let end = (start + ATTEMPT_BATCH).min(max_attempts);
                        let mut processed = 0u64;
                        let mut attempt = start;

                        while attempt < end {
                            if found.load(Ordering::Acquire) {
                                stop = true;
                                break;
                            }

                            if worker_idx == 0 && attempt != 0 && attempt % PROGRESS_INTERVAL == 0 {
                                println!("Checked {} salts...", attempt);
                            }

                            let attempt_number = attempt;
                            attempt += 1;
                            processed += 1;

                            let salt = salt_from_attempt(base_seed, attempt_number);
                            set_salt(&mut data, &salt);
                            let address = compute_address_from_data(&data);

                            if matches_pattern(
                                &address,
                                prefix.as_deref(),
                                suffix.as_deref(),
                                checksum_mode,
                            ) {
                                let mut guard = result.lock().expect("poisoned mutex");
                                *guard = Some((salt, address, attempt_number + 1));
                                found.store(true, Ordering::Release);
                                stop = true;
                                break;
                            }
                        }

                        if processed == 0 {
                            continue;
                        }

                        let total =
                            attempts_done.fetch_add(processed, Ordering::Relaxed) + processed;
                        if let Some(writer) = checkpoint.as_ref() {
                            writer.maybe_write(total);
                        }
                        if stop {
                            break;
                        }
                    }
                });
            }
        });
    });

    let elapsed = start.elapsed();
    let attempts_made = attempts_done.load(Ordering::Relaxed).min(max_attempts);
    if let Some((salt, address, attempts_needed)) = result.lock().unwrap().take() {
        println!();
        println!(
            "Found match after {} attempts ({:.2?})",
            attempts_needed, elapsed
        );
        println!("Salt      : {}", format_hex(&salt));
        println!("Address   : {}", format_hex(&address));
        let checksum = checksum_address(&address);
        println!("Checksum  : {}", checksum);
        println!("Init hash : {}", format_hex(&init_hash));

        let report = SearchResult {
            factory: format_hex(&factory),
            salt: format_hex(&salt),
            address: format_hex(&address),
            checksum,
            init_hash: format_hex(&init_hash),
            attempts: attempts_needed,
            attempts_limit: if max_attempts == u64::MAX {
                None
            } else {
                Some(max_attempts)
            },
            seed: base_seed,
            prefix: prefix.clone(),
            suffix: suffix.clone(),
            checksum_match: checksum_mode,
            artifact: artifact_path_str.clone(),
            bytecode_source: bytecode_source.clone(),
            constructor_args: args.constructor_args.clone(),
        };
        match append_result_file(&output_path, &report) {
            Ok(_) => println!("Result saved to {}", output_path.display()),
            Err(err) => eprintln!(
                "Failed to write result file {}: {err:?}",
                output_path.display()
            ),
        }
    } else {
        println!();
        println!(
            "No match found after {} attempts ({:.2?}). Increase --attempts or relax prefix/suffix.",
            attempts_made, elapsed
        );
    }

    if let Some(writer) = checkpoint_writer.as_ref() {
        writer.force_write(attempts_made)?;
    }

    Ok(())
}

fn load_artifact(path: &PathBuf) -> Result<Artifact> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read artifact at {}", path.display()))?;
    let artifact: Artifact = serde_json::from_str(&raw)
        .context("Failed to parse artifact JSON (missing `bytecode`?)")?;
    Ok(artifact)
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    Ok(Vec::from_hex(trimmed)?)
}

fn parse_address(value: &str) -> Result<[u8; 20]> {
    let bytes = parse_hex_bytes(value)?;
    if bytes.len() != 20 {
        return Err(anyhow!("Address must be 20 bytes (40 hex chars)"));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_salt(value: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_bytes(value)?;
    if bytes.len() != 32 {
        return Err(anyhow!("Salt must be 32 bytes (64 hex chars)"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn compute_address(factory: &[u8; 20], salt: &[u8; 32], init_hash: &[u8; 32]) -> [u8; 20] {
    let mut data = build_data_template(factory, init_hash);
    set_salt(&mut data, salt);
    compute_address_from_data(&data)
}

fn build_data_template(factory: &[u8; 20], init_hash: &[u8; 32]) -> [u8; 85] {
    let mut data = [0u8; 1 + 20 + 32 + 32];
    data[0] = 0xff;
    data[1..21].copy_from_slice(factory);
    data[53..85].copy_from_slice(init_hash);
    data
}

fn set_salt(buffer: &mut [u8; 85], salt: &[u8; 32]) {
    buffer[21..53].copy_from_slice(salt);
}

fn compute_address_from_data(data: &[u8; 85]) -> [u8; 20] {
    let hash = keccak(data);

    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

fn keccak(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn matches_pattern(
    address: &[u8; 20],
    prefix: Option<&str>,
    suffix: Option<&str>,
    checksum_mode: bool,
) -> bool {
    let candidate = if checksum_mode {
        checksum_hex(address)
    } else {
        hex::encode(address)
    };
    if let Some(p) = prefix {
        if !candidate.starts_with(p) {
            return false;
        }
    }
    if let Some(s) = suffix {
        if !candidate.ends_with(s) {
            return false;
        }
    }
    true
}

fn format_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn salt_from_attempt(base_seed: u64, attempt: u64) -> [u8; 32] {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&base_seed.to_le_bytes());
    input[8..].copy_from_slice(&attempt.to_le_bytes());
    keccak(&input)
}

fn config_fingerprint(
    base_seed: u64,
    factory: &[u8; 20],
    init_hash: &[u8; 32],
    prefix: &Option<String>,
    suffix: &Option<String>,
    checksum_mode: bool,
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(factory);
    data.extend_from_slice(init_hash);
    data.extend_from_slice(&base_seed.to_le_bytes());
    data.push(if checksum_mode { 1 } else { 0 });
    if let Some(p) = prefix {
        data.extend_from_slice(p.as_bytes());
        data.push(0xff);
    }
    if let Some(s) = suffix {
        data.extend_from_slice(s.as_bytes());
        data.push(0x01);
    }
    keccak(&data)
}

fn load_checkpoint_file(path: &Path) -> Result<CheckpointFile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Unable to read checkpoint {}", path.display()))?;
    let checkpoint: CheckpointFile = serde_json::from_str(&raw)
        .with_context(|| format!("Invalid checkpoint JSON {}", path.display()))?;
    if checkpoint.version != 1 {
        return Err(anyhow!(
            "Unsupported checkpoint version {}",
            checkpoint.version
        ));
    }
    Ok(checkpoint)
}

fn save_checkpoint_file(path: &Path, payload: &CheckpointFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create checkpoint dir {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(payload)?;
    fs::write(path, data)
        .with_context(|| format!("Failed to write checkpoint {}", path.display()))?;
    Ok(())
}

fn append_result_file(path: &Path, report: &SearchResult) -> Result<()> {
    let mut entries: Vec<Value> = Vec::new();
    if path.exists() {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read existing result file {}", path.display()))?;
        if !raw.trim().is_empty() {
            let existing: Value = serde_json::from_str(&raw).with_context(|| {
                format!("Failed to parse existing result file {}", path.display())
            })?;
            match existing {
                Value::Array(arr) => {
                    entries = arr;
                }
                other => {
                    entries.push(other);
                }
            }
        }
    }
    entries.push(serde_json::to_value(report)?);
    let data = serde_json::to_vec_pretty(&entries)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create result dir {}", parent.display()))?;
    }
    fs::write(path, data)
        .with_context(|| format!("Failed to write result file {}", path.display()))?;
    Ok(())
}

fn checksum_address(address: &[u8; 20]) -> String {
    format!("0x{}", checksum_hex(address))
}

fn checksum_hex(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = keccak(lower.as_bytes());
    let mut result = String::with_capacity(40);
    for (i, ch) in lower.chars().enumerate() {
        if ch.is_ascii_digit() {
            result.push(ch);
            continue;
        }

        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };

        if nibble >= 8 {
            result.push(ch.to_ascii_uppercase());
        } else {
            result.push(ch);
        }
    }
    result
}

fn encode_constructor(
    bytecode_hex: String,
    artifact: &Artifact,
    args: &[String],
) -> Result<String> {
    let abi_bytes = serde_json::to_vec(&artifact.abi)?;
    let mut cursor = Cursor::new(abi_bytes);
    let contract = Contract::load(&mut cursor).context("Failed to parse ABI from artifact")?;
    let constructor = contract
        .constructor()
        .ok_or_else(|| anyhow!("Artifact ABI does not define a constructor"))?;
    if constructor.inputs.len() != args.len() {
        return Err(anyhow!(
            "Constructor expects {} arguments but {} provided",
            constructor.inputs.len(),
            args.len()
        ));
    }
    let mut tokens = Vec::with_capacity(args.len());
    for (param, value) in constructor.inputs.iter().zip(args.iter()) {
        let token = LenientTokenizer::tokenize(&param.kind, value).with_context(|| {
            format!(
                "Failed to parse constructor arg '{}' for type {:?}",
                value, param.kind
            )
        })?;
        tokens.push(token);
    }
    let bytecode = parse_hex_bytes(&bytecode_hex)?;
    let encoded = constructor
        .encode_input(bytecode.clone(), &tokens)
        .context("Failed to encode constructor arguments")?;
    Ok(format_hex(&encoded))
}
