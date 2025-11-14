use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic};
use clap::Parser;
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use rand::Rng;
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

const ATTEMPT_BATCH: u64 = 2048;
const PROGRESS_INTERVAL: u64 = 100_000;

#[derive(Parser, Debug)]
#[command(name = "eoa-vanity")]
#[command(about = "Brute force EOA private keys for vanity addresses", long_about = None)]
struct Args {
    /// Require the address/checksum to start with this hex prefix (no 0x)
    #[arg(long)]
    prefix: Option<String>,

    /// Require the address/checksum to end with this hex suffix (no 0x)
    #[arg(long)]
    suffix: Option<String>,

    /// Match prefix/suffix against the EIP-55 checksum (case-sensitive)
    #[arg(long)]
    checksum_match: bool,

    /// Maximum attempts before giving up (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    attempts: u64,

    /// Number of worker threads (defaults to CPU cores)
    #[arg(long)]
    threads: Option<usize>,

    /// Optional deterministic RNG seed (u64). Enables reproducible or sharded searches.
    #[arg(long)]
    seed: Option<u64>,

    /// Optional path to append JSON results when a key is found.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Path to write periodic checkpoint JSON (stores the next attempt + config hash).
    #[arg(long)]
    checkpoint: Option<PathBuf>,

    /// Resume search from an existing checkpoint file.
    #[arg(long)]
    resume: Option<PathBuf>,

    /// Attempts between checkpoint flushes (only used with --checkpoint).
    #[arg(long, default_value_t = 100_000)]
    checkpoint_interval: u64,

    /// Generate BIP-39 mnemonics and derive keys instead of outputting raw private keys.
    #[arg(long)]
    mnemonic: bool,

    /// HD derivation path used when --mnemonic is enabled.
    #[arg(long, default_value = "m/44'/60'/0'/0/0")]
    hd_path: String,

    /// Derive the key/mnemonic for a specific attempt index (requires --seed) and exit.
    #[arg(long)]
    derive_attempt: Option<u64>,

    /// Seconds between progress stats (0 disables periodic stats).
    #[arg(long, default_value_t = 5)]
    stats_interval: u64,

    /// Emit JSON progress stats instead of plain text.
    #[arg(long)]
    stats_json: bool,
}

#[derive(Serialize)]
struct VanityResult {
    private_key: String,
    public_key: String,
    address: String,
    checksum: String,
    attempts: u64,
    attempts_limit: Option<u64>,
    seed: u64,
    prefix: Option<String>,
    suffix: Option<String>,
    checksum_match: bool,
    mnemonic: Option<String>,
    hd_path: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CheckpointFile {
    version: u32,
    next_attempt: u64,
    base_seed: u64,
    config_hash: String,
}

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

#[derive(Serialize)]
struct ProgressStats {
    attempts: u64,
    attempts_per_sec: f64,
    elapsed_ms: u128,
}

#[derive(Clone)]
enum KeyMode {
    Raw,
    Mnemonic {
        path: DerivationPath,
        path_string: String,
    },
}

struct CandidateKey {
    secret: SecretKey,
    mnemonic: Option<String>,
}

impl KeyMode {
    fn path_string(&self) -> Option<&str> {
        match self {
            KeyMode::Raw => None,
            KeyMode::Mnemonic { path_string, .. } => Some(path_string.as_str()),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

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
    let provided_seed = args.seed;
    let mut base_seed = provided_seed.unwrap_or_else(|| rand::thread_rng().gen());
    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("results/vanity-eoa.json"));

    let key_mode = if args.mnemonic {
        let path = DerivationPath::from_str(&args.hd_path).with_context(|| {
            format!("Invalid --hd-path '{}': expected BIP32 path", args.hd_path)
        })?;
        KeyMode::Mnemonic {
            path,
            path_string: args.hd_path.clone(),
        }
    } else {
        KeyMode::Raw
    };
    let key_mode = Arc::new(key_mode);

    if let Some(target_attempt) = args.derive_attempt {
        if provided_seed.is_none() {
            return Err(anyhow!("--derive-attempt requires --seed"));
        }
        let candidate = derive_candidate(base_seed, target_attempt, key_mode.as_ref())
            .ok_or_else(|| anyhow!("Failed to derive attempt {}", target_attempt))?;
        let address = address_from_secret(&candidate.secret);
        let checksum = checksum_address(&address);
        println!("Derived attempt {}", target_attempt);
        let private_key = candidate.secret.to_bytes();
        let public_key = public_key_bytes(&candidate.secret);
        println!("Private   : 0x{}", hex::encode(private_key));
        println!("Public    : 0x{}", hex::encode(&public_key));
        println!("Address   : {}", format_hex(&address));
        println!("Checksum  : {}", checksum);
        if let Some(phrase) = candidate.mnemonic.as_ref() {
            println!("Mnemonic  : {}", phrase);
            if let KeyMode::Mnemonic { path_string, .. } = key_mode.as_ref() {
                println!("HD path   : {}", path_string);
            }
        }
        return Ok(());
    }

    let prefix = prepare_pattern(args.prefix.clone(), args.checksum_match)?;
    let suffix = prepare_pattern(args.suffix.clone(), args.checksum_match)?;
    if prefix.is_none() && suffix.is_none() {
        return Err(anyhow!("Provide --prefix and/or --suffix"));
    }

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
        &prefix,
        &suffix,
        checksum_mode,
        key_mode.as_ref(),
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

    println!("Searching for vanity EOA...");
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
    println!("Output    : {}", output_path.display());
    match key_mode.as_ref() {
        KeyMode::Raw => println!("Mode      : raw private keys"),
        KeyMode::Mnemonic { path_string, .. } => {
            println!("Mode      : BIP-39 mnemonic (path {})", path_string)
        }
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
    if args.stats_interval > 0 {
        println!(
            "Stats     : every {}s ({})",
            args.stats_interval,
            if args.stats_json { "json" } else { "text" }
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
    let stats_stop = Arc::new(AtomicBool::new(false));
    let stats_handle = spawn_stats_thread(
        args.stats_interval,
        args.stats_json,
        Arc::clone(&attempts_done),
        Arc::clone(&stats_stop),
        start,
    );

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
                let prefix = prefix.clone();
                let suffix = suffix.clone();
                let checksum_mode = checksum_mode;
                let checkpoint = checkpoint_writer.clone();
                let key_mode = Arc::clone(&key_mode);

                s.spawn(move |_| {
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

                        for attempt in start..end {
                            if found.load(Ordering::Acquire) {
                                stop = true;
                                break;
                            }

                            if worker_idx == 0 && attempt != 0 && attempt % PROGRESS_INTERVAL == 0 {
                                println!("Checked {} keys...", attempt);
                            }

                            processed += 1;

                            let attempt_number = attempt;
                            let candidate = match derive_candidate(
                                base_seed,
                                attempt_number,
                                key_mode.as_ref(),
                            ) {
                                Some(value) => value,
                                None => continue,
                            };
                            let address = address_from_secret(&candidate.secret);

                            if matches_pattern(
                                &address,
                                prefix.as_deref(),
                                suffix.as_deref(),
                                checksum_mode,
                            ) {
                                let mut guard = result.lock().expect("poisoned mutex");
                                *guard = Some((candidate, address, attempt_number + 1));
                                found.store(true, Ordering::Release);
                                stop = true;
                                break;
                            }
                        }

                        if processed != 0 {
                            let total =
                                attempts_done.fetch_add(processed, Ordering::Relaxed) + processed;
                            if let Some(writer) = checkpoint.as_ref() {
                                writer.maybe_write(total);
                            }
                        }

                        if stop {
                            break;
                        }
                    }
                });
            }
        });
    });

    stats_stop.store(true, Ordering::Release);
    if let Some(handle) = stats_handle {
        let _ = handle.join();
    }

    let elapsed = start.elapsed();
    let attempts_made = attempts_done.load(Ordering::Relaxed).min(max_attempts);
    if let Some((candidate, address, attempts_needed)) = result.lock().unwrap().take() {
        println!();
        println!(
            "Found vanity key after {} attempts ({:.2?})",
            attempts_needed, elapsed
        );
        let private_key = candidate.secret.to_bytes();
        let public_key = public_key_bytes(&candidate.secret);
        println!("Private   : 0x{}", hex::encode(private_key));
        println!("Public    : 0x{}", hex::encode(&public_key));
        println!("Address   : {}", format_hex(&address));
        let checksum = checksum_address(&address);
        println!("Checksum  : {}", checksum);
        if let Some(phrase) = candidate.mnemonic.as_ref() {
            println!("Mnemonic  : {}", phrase);
        }

        let report = VanityResult {
            private_key: format!("0x{}", hex::encode(private_key)),
            public_key: format!("0x{}", hex::encode(public_key)),
            address: format_hex(&address),
            checksum,
            attempts: attempts_needed,
            attempts_limit: if max_attempts == u64::MAX {
                None
            } else {
                Some(max_attempts)
            },
            seed: base_seed,
            prefix,
            suffix,
            checksum_match: checksum_mode,
            mnemonic: candidate.mnemonic.clone(),
            hd_path: key_mode.as_ref().path_string().map(|s| s.to_string()),
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
            "No vanity key found after {} attempts ({:.2?}). Increase --attempts or relax prefix/suffix.",
            attempts_made, elapsed
        );
    }

    if let Some(writer) = checkpoint_writer.as_ref() {
        writer.force_write(attempts_made)?;
    }

    Ok(())
}

fn prepare_pattern(pattern: Option<String>, checksum_mode: bool) -> Result<Option<String>> {
    pattern
        .map(|value| {
            ensure_hex(&value)?;
            if checksum_mode {
                Ok(value)
            } else {
                Ok(value.to_ascii_lowercase())
            }
        })
        .transpose()
}

fn ensure_hex(value: &str) -> Result<()> {
    if value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(anyhow!("Pattern '{}' contains non-hex characters", value))
    }
}

fn address_from_secret(secret: &SecretKey) -> [u8; 20] {
    let public = secret.public_key();
    let encoded = public.to_encoded_point(false);
    let public_bytes = encoded.as_bytes();
    let hash = keccak(&public_bytes[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

fn public_key_bytes(secret: &SecretKey) -> Vec<u8> {
    secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn matches_pattern(
    address: &[u8; 20],
    prefix: Option<&str>,
    suffix: Option<&str>,
    checksum_mode: bool,
) -> bool {
    if checksum_mode {
        let check = checksum_hex(address);
        if let Some(p) = prefix {
            if !check.starts_with(p) {
                return false;
            }
        }
        if let Some(s) = suffix {
            if !check.ends_with(s) {
                return false;
            }
        }
        return true;
    }

    let lower = hex::encode(address);
    if let Some(p) = prefix {
        if !lower.starts_with(p) {
            return false;
        }
    }
    if let Some(s) = suffix {
        if !lower.ends_with(s) {
            return false;
        }
    }
    true
}

fn derive_candidate(base_seed: u64, attempt: u64, mode: &KeyMode) -> Option<CandidateKey> {
    match mode {
        KeyMode::Raw => {
            let material = key_material_from_attempt(base_seed, attempt);
            let secret = SecretKey::from_slice(&material).ok()?;
            Some(CandidateKey {
                secret,
                mnemonic: None,
            })
        }
        KeyMode::Mnemonic { path, .. } => {
            let entropy = key_material_from_attempt(base_seed, attempt);
            let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).ok()?;
            let phrase = mnemonic.to_string();
            let seed = mnemonic.to_seed("");
            let child = XPrv::derive_from_path(&seed, path).ok()?;
            let signing_key = child.private_key();
            let secret = SecretKey::from_slice(&signing_key.to_bytes()).ok()?;
            Some(CandidateKey {
                secret,
                mnemonic: Some(phrase),
            })
        }
    }
}

fn key_material_from_attempt(base_seed: u64, attempt: u64) -> [u8; 32] {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&base_seed.to_le_bytes());
    input[8..].copy_from_slice(&attempt.to_le_bytes());
    keccak(&input)
}

fn config_fingerprint(
    base_seed: u64,
    prefix: &Option<String>,
    suffix: &Option<String>,
    checksum_mode: bool,
    mode: &KeyMode,
) -> [u8; 32] {
    let mut data = Vec::new();
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
    match mode {
        KeyMode::Raw => data.push(0x11),
        KeyMode::Mnemonic { path_string, .. } => {
            data.push(0x22);
            data.extend_from_slice(path_string.as_bytes());
        }
    }
    keccak(&data)
}

fn spawn_stats_thread(
    interval_secs: u64,
    json_mode: bool,
    attempts_done: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    start: Instant,
) -> Option<thread::JoinHandle<()>> {
    if interval_secs == 0 {
        return None;
    }
    let interval = Duration::from_secs(interval_secs.max(1));
    Some(thread::spawn(move || loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        thread::sleep(interval);
        if stop.load(Ordering::Acquire) {
            break;
        }
        let elapsed = start.elapsed();
        let elapsed_ms = elapsed.as_millis();
        if elapsed_ms == 0 {
            continue;
        }
        let attempts = attempts_done.load(Ordering::Relaxed);
        let elapsed_secs = elapsed.as_secs_f64().max(f64::EPSILON);
        let stats = ProgressStats {
            attempts,
            attempts_per_sec: attempts as f64 / elapsed_secs,
            elapsed_ms,
        };
        if json_mode {
            match serde_json::to_string(&stats) {
                Ok(line) => println!("STATS {line}"),
                Err(err) => eprintln!("Failed to serialize stats: {err:?}"),
            }
        } else {
            println!(
                "Stats | attempts={} | rate={:.2}/s | elapsed={:.2?}",
                stats.attempts, stats.attempts_per_sec, elapsed
            );
        }
    }))
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

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
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

fn format_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn append_result_file(path: &Path, report: &VanityResult) -> Result<()> {
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
