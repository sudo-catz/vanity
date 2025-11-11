use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hex::FromHex;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rayon::ThreadPoolBuilder;
use serde::Deserialize;
use tiny_keccak::{Hasher, Keccak};

#[derive(Parser, Debug)]
#[command(name = "create2-vanity")]
#[command(about = "Brute force CREATE2 salts for vanity contract addresses", long_about = None)]
struct Args {
    /// Deployed Create2Factory address (20-byte hex)
    #[arg(long)]
    factory: String,

    /// Path to Hardhat artifact JSON (must include `bytecode`)
    #[arg(long, default_value = "artifacts/contracts/SimpleStorage.sol/SimpleStorage.json")]
    artifact: PathBuf,

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
}

#[derive(Deserialize)]
struct Artifact {
    bytecode: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let factory = parse_address(&args.factory)?;
    let artifact = load_artifact(&args.artifact)?;
    let bytecode = parse_hex_bytes(&artifact.bytecode)?.into_boxed_slice();
    if bytecode.is_empty() {
        return Err(anyhow!("Artifact bytecode is empty"));
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

    println!("Searching for vanity salt...");
    println!("Factory   : {}", format_hex(&factory));
    println!("Artifact  : {}", args.artifact.display());
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

    let start = Instant::now();
    let counter = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(Mutex::new(None));

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .context("Failed to build rayon thread pool")?;

    pool.install(|| {
        rayon::scope(|s| {
            for _ in 0..threads {
                let counter = Arc::clone(&counter);
                let found = Arc::clone(&found);
                let result = Arc::clone(&result);
                let factory = factory;
                let init_hash = init_hash;
                let prefix = prefix.clone();
                let suffix = suffix.clone();
                let checksum_mode = checksum_mode;

                s.spawn(move |_| {
                    let mut rng = StdRng::from_entropy();
                    loop {
                        if found.load(Ordering::Acquire) {
                            break;
                        }

                        let attempt = counter.fetch_add(1, Ordering::Relaxed);
                        if attempt >= max_attempts {
                            break;
                        }

                        if attempt != 0 && attempt % 10_000 == 0 {
                            println!("Checked {} salts...", attempt);
                        }

                        let salt = random_salt(&mut rng);
                        let address = compute_address(&factory, &salt, &init_hash);
                        if matches_pattern(
                            &address,
                            prefix.as_deref(),
                            suffix.as_deref(),
                            checksum_mode,
                        ) {
                            let mut guard = result.lock().expect("poisoned mutex");
                            *guard = Some((salt, address, attempt + 1));
                            found.store(true, Ordering::Release);
                            break;
                        }
                    }
                });
            }
        });
    });

    let elapsed = start.elapsed();
    let attempts_made = counter.load(Ordering::Relaxed).min(max_attempts);
    if let Some((salt, address, attempts_needed)) = result.lock().unwrap().take() {
        println!();
        println!("Found match after {} attempts ({:.2?})", attempts_needed, elapsed);
        println!("Salt      : {}", format_hex(&salt));
        println!("Address   : {}", format_hex(&address));
        println!("Checksum  : {}", checksum_address(&address));
        println!("Init hash : {}", format_hex(&init_hash));
    } else {
        println!();
        println!(
            "No match found after {} attempts ({:.2?}). Increase --attempts or relax prefix/suffix.",
            attempts_made, elapsed
        );
    }

    Ok(())
}

fn load_artifact(path: &PathBuf) -> Result<Artifact> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read artifact at {}", path.display()))?;
    let artifact: Artifact =
        serde_json::from_str(&raw).context("Failed to parse artifact JSON (missing `bytecode`?)")?;
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
    let mut data = [0u8; 1 + 20 + 32 + 32];
    data[0] = 0xff;
    data[1..21].copy_from_slice(factory);
    data[21..53].copy_from_slice(salt);
    data[53..85].copy_from_slice(init_hash);

    let hash = keccak(&data);

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

fn random_salt(rng: &mut StdRng) -> [u8; 32] {
    rng.gen::<[u8; 32]>()
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
