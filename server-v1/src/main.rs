mod attestation;
mod clock;
mod key;
mod web;

use attestation::{from_text, hex, parse_hex_32, to_text};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use std::{env, fs, net::SocketAddr, path::{Path, PathBuf}, time::Duration};
use tokio::net::TcpListener;
use web::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") | None => serve().await,
        Some("keygen") => keygen(&args[2..]),
        Some("decode") => decode_cmd(&args[2..]),
        Some("verify") => verify_cmd(&args[2..]),
        Some("hash") => hash_cmd(&args[2..]),
        Some("help") | Some("--help") | Some("-h") => { help(); Ok(()) }
        Some(other) => Err(format!("unknown command: {other}\nRun with --help for usage.").into()),
    }
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let bind: SocketAddr = env::var("MUZE_ATTEST_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into()).parse()?;
    let key_path = PathBuf::from(env::var("MUZE_ATTEST_KEY").unwrap_or_else(|_| "data/signing.key".into()));
    let issuer = env::var("MUZE_ATTEST_ISSUER").unwrap_or_else(|_| "Muze Temporal Attestation Service".into());
    let public_base = env::var("MUZE_ATTEST_PUBLIC_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));

    let mut clock_config = clock::ClockConfig::default();
    if let Ok(sources) = env::var("MUZE_ATTEST_NTP_SOURCES") {
        clock_config.sources = sources
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    clock_config.min_valid_sources = env_usize("MUZE_ATTEST_NTP_MIN_VALID", clock_config.min_valid_sources)?;
    clock_config.source_threshold_ms = env_f64("MUZE_ATTEST_NTP_SOURCE_THRESHOLD_MS", clock_config.source_threshold_ms)?;
    clock_config.local_threshold_ms = env_f64("MUZE_ATTEST_NTP_LOCAL_THRESHOLD_MS", clock_config.local_threshold_ms)?;
    clock_config.check_interval = Duration::from_secs(env_u64("MUZE_ATTEST_NTP_CHECK_INTERVAL_SECS", clock_config.check_interval.as_secs())?);
    clock_config.stale_after = Duration::from_secs(env_u64("MUZE_ATTEST_NTP_STALE_AFTER_SECS", clock_config.stale_after.as_secs())?);
    clock_config.query_timeout = Duration::from_millis(env_u64("MUZE_ATTEST_NTP_TIMEOUT_MS", clock_config.query_timeout.as_millis() as u64)?);

    if clock_config.sources.len() < clock_config.min_valid_sources {
        return Err(format!("MUZE_ATTEST_NTP_MIN_VALID={} but only {} NTP sources are configured", clock_config.min_valid_sources, clock_config.sources.len()).into());
    }

    let clock_monitor = clock::ClockMonitor::new(clock_config);
    clock_monitor.clone().spawn();

    let (signing_key, created) = key::load_or_create(&key_path)?;
    if created {
        eprintln!("Generated new Ed25519 signing key at {}", key_path.display());
        eprintln!("Keep this file stable across restarts; changing it changes the issuer key identity.");
    }
    let kid = hex(&attestation::key_id(&signing_key.verifying_key()));
    eprintln!("Muze Temporal Attestation Service");
    eprintln!("Listening on http://{bind}");
    eprintln!("Issuer: {issuer}");
    eprintln!("Key ID: {kid}");
    eprintln!("Assurance level: 1 (trusted issuer upper-bound timestamp)");
    eprintln!("Clock health: NTP consensus enabled ({} sources, minimum {} valid)", clock_monitor.config().sources.len(), clock_monitor.config().min_valid_sources);
    eprintln!("Clock sources: {}", clock_monitor.config().sources.join(", "));

    let state = AppState::new(signing_key, issuer, public_base, clock_monitor);
    let listener = TcpListener::bind(bind).await?;
    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, _) = accept?;
                let io = TokioIo::new(stream);
                let st = state.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| web::handle(req, st.clone()));
                    if let Err(err) = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await {
                        eprintln!("connection error: {err}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("Shutting down.");
                break;
            }
        }
    }
    Ok(())
}

fn keygen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = args.get(0).map(String::as_str).unwrap_or("data/signing.key");
    let force = args.iter().any(|x| x == "--force");
    key::generate(Path::new(path), force)?;
    let bytes = fs::read(path)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let sk = SigningKey::from_bytes(&seed);
    println!("created: {path}");
    println!("key id : {}", hex(&attestation::key_id(&sk.verifying_key())));
    println!("public : {}", web::public_key_json(&sk.verifying_key(), "Muze Temporal Attestation Service"));
    Ok(())
}

fn decode_cmd(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let input = args.get(0).ok_or("usage: muze-temporal-attestation decode <mta1_...|file>")?;
    let raw = if input.starts_with(attestation::TEXT_PREFIX) {
        from_text(input)?
    } else {
        fs::read(input)?
    };
    let a = attestation::decode(&raw)?;
    println!("format version : {}", a.format_version);
    println!("assurance level: {}", a.assurance_level);
    println!("hash algorithm : {}", a.hash_algorithm);
    println!("digest         : {}", hex(&a.digest));
    println!("timestamp ms   : {}", a.timestamp_ms);
    println!("key id         : {}", hex(&a.key_id));
    println!("text form      : {}", to_text(&raw));
    println!();
    println!("Meaning (level 1): the issuer represented by key {} attests that this commitment was available to it no later than Unix time {} ms.", hex(&a.key_id), a.timestamp_ms);
    println!("Signature has NOT been verified by this decode-only command. Use `verify` with a public key file.");
    Ok(())
}

fn verify_cmd(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() < 2 {
        return Err("usage: muze-temporal-attestation verify <attestation-file|mta1_...> <public-key-file> [data-file]".into());
    }
    let raw = if args[0].starts_with(attestation::TEXT_PREFIX) { from_text(&args[0])? } else { fs::read(&args[0])? };
    let pub_bytes = fs::read(&args[1])?;
    if pub_bytes.len() != 32 { return Err("public-key-file must contain exactly 32 raw Ed25519 public-key bytes".into()); }
    let mut pk = [0u8; 32]; pk.copy_from_slice(&pub_bytes);
    let vk = VerifyingKey::from_bytes(&pk)?;
    let decoded = attestation::verify(&raw, &vk)?;
    println!("VALID signature");
    println!("assurance level: {}", decoded.assurance_level);
    println!("digest: {}", hex(&decoded.digest));
    println!("timestamp ms: {}", decoded.timestamp_ms);
    if let Some(data_path) = args.get(2) {
        let data = fs::read(data_path)?;
        let actual = Sha256::digest(&data);
        if actual.as_slice() == decoded.digest {
            println!("content match: YES ({data_path})");
        } else {
            return Err("content does not match attested digest".into());
        }
    }
    Ok(())
}

fn hash_cmd(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = args.get(0).ok_or("usage: muze-temporal-attestation hash <file>")?;
    let data = fs::read(path)?;
    println!("{}", hex(&Sha256::digest(&data)));
    Ok(())
}

fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(v) => Ok(v.parse().map_err(|e| format!("invalid {name}={v:?}: {e}"))?),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(e.into()),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(v) => Ok(v.parse().map_err(|e| format!("invalid {name}={v:?}: {e}"))?),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(e.into()),
    }
}

fn env_f64(name: &str, default: f64) -> Result<f64, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(v) => Ok(v.parse().map_err(|e| format!("invalid {name}={v:?}: {e}"))?),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(e.into()),
    }
}

fn help() {
    println!(r#"Muze Temporal Attestation Service prototype

USAGE:
  muze-temporal-attestation serve
  muze-temporal-attestation keygen [path] [--force]
  muze-temporal-attestation hash <file>
  muze-temporal-attestation decode <mta1_...|attestation-file>
  muze-temporal-attestation verify <attestation-file|mta1_...> <raw-public-key-file> [data-file]

SERVER ENVIRONMENT:
  MUZE_ATTEST_BIND             default 127.0.0.1:3000
  MUZE_ATTEST_KEY              default data/signing.key
  MUZE_ATTEST_ISSUER           default "Muze Temporal Attestation Service"
  MUZE_ATTEST_PUBLIC_BASE_URL  informational base URL
  MUZE_ATTEST_NTP_SOURCES      comma-separated NTP hosts
  MUZE_ATTEST_NTP_MIN_VALID    default 3
  MUZE_ATTEST_NTP_SOURCE_THRESHOLD_MS  default 100
  MUZE_ATTEST_NTP_LOCAL_THRESHOLD_MS   default 250
  MUZE_ATTEST_NTP_CHECK_INTERVAL_SECS  default 30
  MUZE_ATTEST_NTP_STALE_AFTER_SECS     default 90
  MUZE_ATTEST_NTP_TIMEOUT_MS            default 2000

API:
  POST /v1/attest              request body = exactly 32 raw SHA-256 digest bytes
  GET  /v1/keys/current        current public key metadata
  GET  /v1/health              machine-readable clock/service health
  POST /v1/decode              verify and explain one raw 127-byte attestation
"#);
}
