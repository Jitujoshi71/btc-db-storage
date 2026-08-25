use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use memmap2::MmapOptions;
use rand::seq::SliceRandom;
use rayon::prelude::*;
use rusqlite::{Connection, OpenFlags};

// Bloom Filter Parameters
const TOTAL_ITEMS: usize = 1_800_000_000;
const FP_RATE: f64 = 0.00000000001; // 1e-11

struct BloomFilterMMAP {
    m: usize,
    k: u32,
    mmap: memmap2::Mmap,
}

impl BloomFilterMMAP {
    fn new(file_path: &str) -> std::io::Result<Self> {
        let n = TOTAL_ITEMS as f64;
        let m = (-(n * FP_RATE.ln()) / (2.0f64.ln().powi(2))).round() as usize;
        let k = (((m as f64) / n) * 2.0f64.ln()).round() as u32;

        let file = File::open(file_path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };

        println!("==================================================");
        println!("🚀 All-Local Verification Engine Active:");
        println!("  - L1 Filter: Bloom Filter ({}) [{:.2} GB, k={}]", file_path, (m as f64) / (8.0 * 1024.0 * 1024.0 * 1024.0), k);
        println!("  - L2 Verifier: Local SQLite Indexed Database");
        println!("==================================================\n");

        Ok(BloomFilterMMAP { m, k, mmap })
    }

    #[inline]
    fn contains(&self, item: &str) -> bool {
        let h: u64 = seahash::hash(item.as_bytes());
        let h1 = (h & 0xFFFFFFFF) as usize;
        let h2 = (h >> 32) as usize;

        for i in 0..self.k {
            let bit_idx = (h1.wrapping_add((i as usize).wrapping_mul(h2))) % self.m;
            let byte_idx = bit_idx / 8;
            let bit_offset = bit_idx % 8;

            if (self.mmap[byte_idx] & (1 << bit_offset)) == 0 {
                return false;
            }
        }
        true
    }
}

// Thread-local SQLite Context
struct ThreadContext {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    db_conn: Connection,
}

impl ThreadContext {
    fn new(db_path: &str) -> Self {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("Failed to open SQLite database for thread");

        conn.execute_batch(
            "PRAGMA query_only = 1;
             PRAGMA synchronous = OFF;
             PRAGMA mmap_size = 30000000000;
             PRAGMA cache_size = -50000;",
        )
        .unwrap();

        ThreadContext {
            secp: Secp256k1::new(),
            db_conn: conn,
        }
    }

    #[inline]
    fn is_in_db(&self, address: &str) -> bool {
        let mut stmt = match self.db_conn.prepare_cached("SELECT 1 FROM addresses WHERE address = ?1 LIMIT 1") {
            Ok(s) => s,
            Err(_) => return false,
        };
        stmt.exists([address]).unwrap_or(false)
    }
}

fn derive_addresses(mnemonic_str: &str, secp: &Secp256k1<bitcoin::secp256k1::All>) -> Option<Vec<String>> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_str).ok()?;
    let seed = mnemonic.to_seed("");
    let root_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).ok()?;

    let paths = [
        "m/44'/0'/0'/0/0", // Legacy P2PKH (1...)
        "m/49'/0'/0'/0/0", // Nested SegWit P2SH (3...)
        "m/84'/0'/0'/0/0", // Native SegWit P2WPKH (bc1q...)
        "m/86'/0'/0'/0/0", // Taproot P2TR (bc1p...)
    ];

    let mut addrs = Vec::with_capacity(4);

    for path_str in &paths {
        let path: DerivationPath = path_str.parse().ok()?;
        let child_key = root_key.derive_priv(secp, &path).ok()?;
        let secp_pk = child_key.to_keypair(secp).public_key();
        let pubkey = bitcoin::PublicKey::new(secp_pk);

        let address = if path_str.starts_with("m/44'") {
            bitcoin::Address::p2pkh(&pubkey, Network::Bitcoin).to_string()
        } else if path_str.starts_with("m/84'") {
            bitcoin::Address::p2wpkh(&pubkey, Network::Bitcoin).ok()?.to_string()
        } else if path_str.starts_with("m/86'") {
            let x_only = bitcoin::secp256k1::XOnlyPublicKey::from(secp_pk);
            bitcoin::Address::p2tr(secp, x_only, None, Network::Bitcoin).to_string()
        } else {
            bitcoin::Address::p2shwpkh(&pubkey, Network::Bitcoin).ok()?.to_string()
        };

        addrs.push(address);
    }

    Some(addrs)
}

fn main() {
    let bloom_file = "btc_0_0000000000001.bin";
    let db_path = "btc_addresses.db";
    let words_file = "words.txt";
    let output_csv = "active_wallets.csv";

    if !Path::new(bloom_file).exists() {
        eprintln!("❌ Error: '{}' file nahi mili!", bloom_file);
        return;
    }

    if !Path::new(db_path).exists() {
        eprintln!("❌ Error: '{}' SQLite database file nahi mili!", db_path);
        return;
    }

    let bf = Arc::new(BloomFilterMMAP::new(bloom_file).expect("Bloom filter load failed"));

    let file = File::open(words_file).expect("words.txt file nahi mili!");
    let reader = BufReader::new(file);
    let words: Vec<String> = reader
        .lines()
        .filter_map(Result::ok)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    println!("Loaded {} words from '{}'", words.len(), words_file);

    if !Path::new(output_csv).exists() {
        let mut out = File::create(output_csv).unwrap();
        writeln!(out, "Seed Phrase,Bitcoin Address,Status").unwrap();
    }

    let batch_size = 10_000;
    let processed_counter = Arc::new(AtomicU64::new(0));
    let active_hits_counter = Arc::new(AtomicU64::new(0));
    let csv_mutex = Arc::new(Mutex::new(()));

    let start_time = Instant::now();
    println!("⚡ Multi-Threaded Local Scanner Running (Zero Latency)...\n");

    loop {
        let mut batch: Vec<String> = Vec::with_capacity(batch_size);
        let mut rng = rand::thread_rng();

        for _ in 0..batch_size {
            let sample: Vec<&String> = words.choose_multiple(&mut rng, 12).collect();
            let phrase = sample.iter().map(|s| s.as_str()).collect::<Vec<&str>>().join(" ");
            batch.push(phrase);
        }

        let bf_ref = Arc::clone(&bf);
        let proc_ref = Arc::clone(&processed_counter);
        let hits_ref = Arc::clone(&active_hits_counter);
        let mutex_ref = Arc::clone(&csv_mutex);

        batch.par_iter().for_each_init(
            || ThreadContext::new(db_path),
            |ctx, phrase| {
                if let Some(addrs) = derive_addresses(phrase, &ctx.secp) {
                    for addr in addrs {
                        // L1: In-Memory Bloom Check
                        if bf_ref.contains(&addr) {
                            // L2: Direct Local SQLite Query (< 0.05ms)
                            if ctx.is_in_db(&addr) {
                                hits_ref.fetch_add(1, Ordering::Relaxed);

                                println!(
                                    "\n\n🔥 [EXACT ACTIVE WALLET MATCH!]\n  Seed: {}\n  Address: {}\n  Source: Local SQLite Verified\n",
                                    phrase, addr
                                );

                                let _guard = mutex_ref.lock().unwrap();
                                let mut out_file = OpenOptions::new().append(true).open(output_csv).unwrap();
                                writeln!(out_file, "\"{}\",\"{}\",Confirmed Active", phrase, addr).unwrap();
                                out_file.flush().unwrap();
                            }
                        }
                    }
                }
            },
        );

        let curr_proc = proc_ref.fetch_add(batch_size as u64, Ordering::Relaxed) + batch_size as u64;
        let elapsed = start_time.elapsed().as_secs_f64();
        let speed = (curr_proc as f64) / elapsed;

        print!(
            "\r⏳ Checked: {} seeds | Confirmed Hits: {} | Speed: {:.1} seeds/sec",
            curr_proc,
            hits_ref.load(Ordering::Relaxed),
            speed
        );
        let _ = std::io::stdout().flush();
    }
}
