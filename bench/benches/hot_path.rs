use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use muze_attest_bench::{
    BenchIssuer, benchmark_commitment, encode_unsigned_receipt, receipt_cid,
};

fn bench_hot_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("attestation_hot_path");
    group.throughput(Throughput::Elements(1));

    let issuer = BenchIssuer::deterministic(1);
    let commitment = benchmark_commitment(42);
    let nonce = [0x11u8; 16];
    let unsigned = encode_unsigned_receipt(&commitment, &nonce, issuer.key_id());

    group.bench_function("ed25519_sign_receipt_body", |b| {
        b.iter(|| black_box(issuer.sign_body(black_box(&unsigned))))
    });

    let mut issuer_for_issue = BenchIssuer::deterministic(2);
    group.bench_function("full_receipt_sign_plus_cid", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter = counter.wrapping_add(1);
            let commitment = benchmark_commitment(counter);
            black_box(issuer_for_issue.issue(black_box(&commitment)))
        })
    });

    let mut issuer_for_cid = BenchIssuer::deterministic(3);
    let (receipt, _cid) = issuer_for_cid.issue(&benchmark_commitment(9));
    group.bench_function("sha256_plus_binary_cid", |b| {
        b.iter(|| black_box(receipt_cid(black_box(&receipt))))
    });

    group.finish();
}

criterion_group!(benches, bench_hot_path);
criterion_main!(benches);
