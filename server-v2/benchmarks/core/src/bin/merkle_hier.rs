//! Hierarchical Merkle benchmark for Muze Temporal Attestation.
//!
//! Default shape mirrors the measured HTTP operating point:
//!   150,000 commitments/second
//!   60 one-second trees
//!   1 minute root over the 60 second roots
//!
//! The goal is to measure the RAM/CPU cost of recursive aggregation without
//! retaining a monolithic ~9M-leaf tree. It also reports the unavoidable size
//! of a *standalone* inclusion witness for each attestation.
//!
//! Prototype only; this is not a protocol specification.

use muze_attest_bench::benchmark_commitment;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    hint::black_box,
    process,
    time::{Duration, Instant},
};

type Hash = [u8; 32];

const DEFAULT_LEAVES_PER_SECOND: usize = 150_000;
const DEFAULT_SECONDS: usize = 60;

#[inline]
fn leaf_hash(commitment: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(commitment);
    h.finalize().into()
}

#[inline]
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn deterministic_leaves(start: usize, count: usize) -> Vec<Hash> {
    let mut leaves = Vec::with_capacity(count);
    for i in 0..count {
        let commitment = benchmark_commitment((start + i) as u64);
        leaves.push(leaf_hash(&commitment));
    }
    leaves
}

fn build_levels(leaves: Vec<Hash>) -> Vec<Vec<Hash>> {
    assert!(!leaves.is_empty());
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let previous = levels.last().unwrap();
        let mut next = Vec::with_capacity((previous.len() + 1) / 2);
        for pair in previous.chunks(2) {
            let left = &pair[0];
            let right = if pair.len() == 2 { &pair[1] } else { left };
            next.push(node_hash(left, right));
        }
        levels.push(next);
    }
    levels
}

#[inline]
fn root(levels: &[Vec<Hash>]) -> Hash {
    levels.last().unwrap()[0]
}

#[inline]
fn depth(levels: &[Vec<Hash>]) -> usize {
    levels.len() - 1
}

#[inline]
fn sibling_at(level: &[Hash], pos: usize) -> &Hash {
    if pos & 1 == 0 {
        let sib = pos + 1;
        if sib < level.len() { &level[sib] } else { &level[pos] }
    } else {
        &level[pos - 1]
    }
}

fn collect_proof(levels: &[Vec<Hash>], index: usize) -> Vec<Hash> {
    let mut proof = Vec::with_capacity(depth(levels));
    let mut pos = index;
    for level in &levels[..levels.len() - 1] {
        proof.push(*sibling_at(level, pos));
        pos /= 2;
    }
    proof
}

#[inline]
fn mix_hash(checksum: &mut u64, hash: &Hash) {
    let mut word = [0u8; 8];
    word.copy_from_slice(&hash[..8]);
    *checksum = checksum.rotate_left(7) ^ u64::from_le_bytes(word);
}

/// Touch every sibling hash needed for every local proof without allocating
/// millions of Vecs. This approximates proof-path extraction cost separately
/// from encoding/storage cost.
fn scan_local_proofs(levels: &[Vec<Hash>], leaf_count: usize) -> (Duration, u64) {
    let started = Instant::now();
    let mut checksum = 0u64;
    for index in 0..leaf_count {
        let mut pos = index;
        for level in &levels[..levels.len() - 1] {
            mix_hash(&mut checksum, sibling_at(level, pos));
            pos /= 2;
        }
    }
    (started.elapsed(), checksum)
}

fn verify_path(mut current: Hash, mut index: usize, proof: &[Hash]) -> Hash {
    for sibling in proof {
        current = if index & 1 == 0 {
            node_hash(&current, sibling)
        } else {
            node_hash(sibling, &current)
        };
        index /= 2;
    }
    current
}

fn proc_kib(field: &str) -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        if line.starts_with(field) {
            line.split_whitespace().nth(1)?.parse::<u64>().ok()
        } else {
            None
        }
    })
}

fn print_memory(label: &str) {
    match (proc_kib("VmRSS:"), proc_kib("VmHWM:")) {
        (Some(rss), Some(hwm)) => println!(
            "{label:<25} RSS={:>8.1} MiB   peak={:>8.1} MiB",
            rss as f64 / 1024.0,
            hwm as f64 / 1024.0
        ),
        _ => println!("{label:<25} memory metrics unavailable"),
    }
}

fn print_rate(label: &str, count: usize, elapsed: Duration, unit: &str) {
    let seconds = elapsed.as_secs_f64();
    println!(
        "{label:<32} {:>8.3} s   {:>13.0} {unit}/s",
        seconds,
        count as f64 / seconds
    );
}

fn print_hash(label: &str, hash: &Hash) {
    print!("{label}: ");
    for b in hash.iter().take(8) { print!("{b:02x}"); }
    println!("…");
}

fn mib(bytes: u128) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn benchmark(leaves_per_second: usize, seconds: usize) {
    assert!(leaves_per_second > 0);
    assert!(seconds > 0);

    let total_leaves = leaves_per_second.checked_mul(seconds).expect("leaf count overflow");
    println!("Muze hierarchical Merkle benchmark");
    println!("leaves/second : {leaves_per_second}");
    println!("seconds       : {seconds}");
    println!("total leaves  : {total_leaves}");
    println!();
    print_memory("baseline");

    let overall = Instant::now();
    let mut second_roots = Vec::with_capacity(seconds);
    let mut local_build = Duration::ZERO;
    let mut local_proof_scan = Duration::ZERO;
    let mut checksum = 0u64;
    let mut local_depth: Option<usize> = None;

    for second in 0..seconds {
        let offset = second * leaves_per_second;
        let started = Instant::now();
        let levels = build_levels(deterministic_leaves(offset, leaves_per_second));
        local_build += started.elapsed();

        let d = depth(&levels);
        match local_depth {
            Some(prev) => assert_eq!(prev, d),
            None => local_depth = Some(d),
        }

        second_roots.push(root(&levels));
        let (elapsed, c) = scan_local_proofs(&levels, leaves_per_second);
        local_proof_scan += elapsed;
        checksum ^= c.rotate_left((second % 63) as u32);

        if second == 0 {
            print_memory("one local tree resident");
        }
        // levels drops here: only the 32-byte second root survives.
    }

    print_rate("all one-second tree builds", total_leaves, local_build, "leaves");
    print_rate("all local proof path scans", total_leaves, local_proof_scan, "proofs");
    print_memory("after local trees dropped");

    let top_started = Instant::now();
    let top_levels = build_levels(second_roots);
    let top_build = top_started.elapsed();
    let minute_root = root(&top_levels);
    let top_depth = depth(&top_levels);
    let local_depth = local_depth.unwrap();

    print_rate("minute-root tree build", seconds, top_build, "roots");
    println!("local proof depth : {local_depth} sibling hashes");
    println!("top proof depth   : {top_depth} sibling hashes");
    println!("combined depth    : {} sibling hashes", local_depth + top_depth);
    print_hash("minute root", &minute_root);

    // Simulate attaching the small shared top-level proof to every leaf.
    // There are only `seconds` unique top proofs; in a standalone client proof
    // the selected top path is repeated for each attestation.
    let top_scan_started = Instant::now();
    for second in 0..seconds {
        let top_proof = collect_proof(&top_levels, second);
        for _ in 0..leaves_per_second {
            for sibling in &top_proof { mix_hash(&mut checksum, sibling); }
        }
    }
    let top_scan = top_scan_started.elapsed();
    print_rate("top proof attachment scan", total_leaves, top_scan, "proofs");

    let siblings = local_depth + top_depth;
    let path_bytes = siblings * 32;
    let standalone_bytes_per_second = (leaves_per_second as u128) * (path_bytes as u128);
    let standalone_bytes_total = (total_leaves as u128) * (path_bytes as u128);

    println!();
    println!("Standalone proof-path economics (hashes only, before metadata):");
    println!("path bytes/proof : {path_bytes} B");
    println!("path output/sec  : {:.2} MiB/s", mib(standalone_bytes_per_second));
    println!("path output/batch: {:.2} MiB", mib(standalone_bytes_total));
    println!("path output/day* : {:.2} TiB", standalone_bytes_per_second as f64 * 86400.0 / (1024.0_f64.powi(4)));
    println!("  *if continuously saturated at this rate and every proof is standalone");

    // Approximate unique Merkle-node material if a whole second tree is shared
    // rather than duplicating sibling hashes into standalone proofs.
    let local_nodes_upper = 2u128 * leaves_per_second as u128;
    let shared_tree_bytes_per_second = local_nodes_upper * 32;
    println!();
    println!("Shared-tree comparison:");
    println!("~unique local tree hash bytes/sec: {:.2} MiB (upper bound)", mib(shared_tree_bytes_per_second));
    println!("This is much smaller than repeating a ~{path_bytes} B path per client,");
    println!("but shared/public nodes have different privacy and availability tradeoffs.");

    // Validate complete two-level proofs for first/middle/last leaf.
    let samples = [0usize, total_leaves / 2, total_leaves - 1];
    for global_index in samples {
        let second = global_index / leaves_per_second;
        let local_index = global_index % leaves_per_second;
        let local_levels = build_levels(deterministic_leaves(second * leaves_per_second, leaves_per_second));
        let local_root = root(&local_levels);
        let local_proof = collect_proof(&local_levels, local_index);
        let top_proof = collect_proof(&top_levels, second);

        let commitment = benchmark_commitment(global_index as u64);
        let after_local = verify_path(leaf_hash(&commitment), local_index, &local_proof);
        assert_eq!(after_local, local_root, "local proof failed at {global_index}");
        let after_top = verify_path(after_local, second, &top_proof);
        assert_eq!(after_top, minute_root, "top proof failed at {global_index}");
    }

    println!();
    print_rate("overall benchmark", total_leaves, overall.elapsed(), "leaves");
    print_memory("final");
    println!("checksum       : {checksum}");
    black_box(top_levels);
}

fn parse_usize(value: Option<String>, default: usize, name: &str) -> usize {
    match value {
        Some(v) => v.parse().unwrap_or_else(|_| {
            eprintln!("invalid {name}: {v}");
            process::exit(2);
        }),
        None => default,
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let leaves_per_second = parse_usize(args.next(), DEFAULT_LEAVES_PER_SECOND, "leaves/second");
    let seconds = parse_usize(args.next(), DEFAULT_SECONDS, "seconds");
    benchmark(leaves_per_second, seconds);
}
