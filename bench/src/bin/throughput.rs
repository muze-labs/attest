use muze_attest_bench::{BenchIssuer, SIGNED_RECEIPT_LEN, RECEIPT_CID_LEN, benchmark_commitment};
use std::{
    hint::black_box,
    sync::{Arc, Barrier},
    thread,
    time::Instant,
};

fn parse_arg(index: usize, default: usize) -> usize {
    std::env::args()
        .nth(index)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

fn single_thread(iterations: usize) -> (f64, u64) {
    let mut issuer = BenchIssuer::deterministic(1);
    let start = Instant::now();
    let mut checksum = 0u64;

    for i in 0..iterations {
        let commitment = benchmark_commitment(i as u64);
        let (_receipt, cid) = issuer.issue(black_box(&commitment));
        checksum = checksum.wrapping_add(cid.bytes[35] as u64);
    }

    let elapsed = start.elapsed().as_secs_f64();
    (iterations as f64 / elapsed, checksum)
}

fn multi_thread(iterations: usize, workers: usize) -> (f64, u64) {
    let barrier = Arc::new(Barrier::new(workers + 1));
    let per_worker = iterations / workers;
    let remainder = iterations % workers;
    let mut handles = Vec::with_capacity(workers);

    for worker in 0..workers {
        let barrier = Arc::clone(&barrier);
        let count = per_worker + usize::from(worker < remainder);
        handles.push(thread::spawn(move || {
            let seed = (worker as u8).wrapping_add(1);
            let mut issuer = BenchIssuer::deterministic(seed);
            barrier.wait();

            let mut checksum = 0u64;
            for i in 0..count {
                let counter = ((worker as u64) << 48) ^ i as u64;
                let commitment = benchmark_commitment(counter);
                let (_receipt, cid) = issuer.issue(black_box(&commitment));
                checksum = checksum.wrapping_add(cid.bytes[35] as u64);
            }
            checksum
        }));
    }

    let start = Instant::now();
    barrier.wait();

    let mut checksum = 0u64;
    for handle in handles {
        checksum = checksum.wrapping_add(handle.join().expect("worker panicked"));
    }

    let elapsed = start.elapsed().as_secs_f64();
    (iterations as f64 / elapsed, checksum)
}

fn main() {
    let iterations = parse_arg(1, 1_000_000);
    let default_workers = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let workers = parse_arg(2, default_workers).max(1);

    println!("Muze temporal-attestation hot-path throughput benchmark");
    println!("receipt bytes : {SIGNED_RECEIPT_LEN}");
    println!("binary CID    : {RECEIPT_CID_LEN} bytes");
    println!("iterations    : {iterations}");
    println!("workers       : {workers}");
    println!();

    let (single_ops, single_checksum) = single_thread(iterations);
    println!("single-thread : {:>12.0} attestations/s  checksum={single_checksum}", single_ops);

    let (multi_ops, multi_checksum) = multi_thread(iterations, workers);
    println!("multi-thread  : {:>12.0} attestations/s  checksum={multi_checksum}", multi_ops);
    println!("scaling       : {:>12.2}x", multi_ops / single_ops);
}
