//! Probe S3-compatible object storage with NippyJar-shaped reads.
//!
//! Times the cold-path (HEAD + eager-load offsets) and warm-path (random small + medium
//! data range GETs) against an `S3JarBackend` pointed at a real bucket. Reports p50/p95/p99
//! latencies — the numbers needed to decide whether running reth's static files from object
//! storage is viable on a given DC + provider combination.
//!
//! ## Usage
//!
//! Set environment variables and run:
//!
//! ```sh
//! export AWS_ACCESS_KEY_ID=...
//! export AWS_SECRET_ACCESS_KEY=...
//! export NIPPY_ENDPOINT=https://fsn1.your-objectstorage.com
//! export NIPPY_REGION=fsn1
//! export NIPPY_BUCKET=reth-mainnet
//! export NIPPY_PREFIX=static_files
//! export NIPPY_SEGMENT=static_file_account-change-sets_24850000_24899999
//! cargo run --example s3_probe --features s3-backend --release
//! ```
//!
//! The segment basename is the on-disk filename (no extension); the probe expects the
//! corresponding `.off` to live next to it in the bucket.

use reth_nippy_jar::{RemoteJarBackend, S3JarBackend, S3JarLocator};
use std::{env, time::Instant};

fn env_var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing env var: {name}"))
}

fn percentile(sorted_micros: &[u128], p: f64) -> u128 {
    if sorted_micros.is_empty() {
        return 0;
    }
    let idx = ((sorted_micros.len() as f64 - 1.0) * p).round() as usize;
    sorted_micros[idx]
}

fn main() {
    let locator = S3JarLocator {
        endpoint: env_var("NIPPY_ENDPOINT"),
        region: env_var("NIPPY_REGION"),
        bucket: env_var("NIPPY_BUCKET"),
        key_prefix: env::var("NIPPY_PREFIX").unwrap_or_default(),
    };
    let segment = env_var("NIPPY_SEGMENT");

    println!("== probe target ==");
    println!("endpoint: {}", locator.endpoint);
    println!("bucket:   {}/{}", locator.bucket, locator.key_prefix);
    println!("segment:  {segment}");
    println!();

    // ---------- cold path: construct backend (HEAD + eager-load offsets) ----------
    let t0 = Instant::now();
    let backend = S3JarBackend::new(&locator, &segment).expect("construct backend");
    let cold_ms = t0.elapsed().as_secs_f64() * 1000.0;

    println!("== cold path ==");
    println!("HEAD + offsets-load:  {cold_ms:8.1} ms");
    println!("data file size:       {:>10} bytes", backend.data_size());
    println!("offsets file size:    {:>10} bytes", backend.offsets_size());
    println!();

    // ---------- warm path: random small range reads ----------
    let n_reads = 200;
    let small_size = 4 * 1024;
    let medium_size = 64 * 1024;

    let mut rng = SimpleRng::new(0xC0FFEE);

    for (label, size) in [("4 KB", small_size), ("64 KB", medium_size)] {
        let mut samples = Vec::with_capacity(n_reads);
        for _ in 0..n_reads {
            let max_start = backend.data_size().saturating_sub(size);
            if max_start == 0 {
                break;
            }
            let start = rng.next_in(max_start as u64) as usize;
            let range = start..start + size;

            let t = Instant::now();
            let bytes = backend.read_data(range).expect("read_data");
            let elapsed = t.elapsed().as_micros();
            samples.push(elapsed);
            assert_eq!(bytes.len(), size, "expected {} bytes, got {}", size, bytes.len());
        }
        samples.sort_unstable();

        let mean = samples.iter().sum::<u128>() / samples.len() as u128;
        let p50 = percentile(&samples, 0.50);
        let p95 = percentile(&samples, 0.95);
        let p99 = percentile(&samples, 0.99);
        let max = *samples.last().unwrap();
        let throughput_mbps = (size as f64 / 1024.0 / 1024.0) / (mean as f64 / 1_000_000.0);

        println!("== warm path: {n_reads} random {label} reads ==");
        println!(
            "mean={:>5} µs  p50={:>5} µs  p95={:>5} µs  p99={:>5} µs  max={:>6} µs  ~{:.1} MB/s/req",
            mean, p50, p95, p99, max, throughput_mbps
        );
        println!();
    }

    // ---------- offsets path: synthetic small reads against the in-memory cache ----------
    let mut samples = Vec::with_capacity(n_reads);
    for _ in 0..n_reads {
        let off_len = backend.offsets_size();
        if off_len < 8 {
            break;
        }
        let start = rng.next_in((off_len - 8) as u64) as usize;
        let range = start..start + 8;
        let t = Instant::now();
        let _ = backend.read_offsets(range).expect("read_offsets");
        samples.push(t.elapsed().as_nanos());
    }
    samples.sort_unstable();
    if !samples.is_empty() {
        println!("== offsets cache: {n_reads} 8B reads (from RAM, sanity check) ==");
        println!(
            "mean={} ns  p50={} ns  p99={} ns",
            samples.iter().sum::<u128>() / samples.len() as u128,
            percentile(&samples, 0.50),
            percentile(&samples, 0.99),
        );
    }
}

/// xorshift — keeps the example deterministic without pulling in `rand`.
struct SimpleRng(u64);
impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn next_in(&mut self, max: u64) -> u64 {
        if max == 0 {
            0
        } else {
            self.next_u64() % max
        }
    }
}
