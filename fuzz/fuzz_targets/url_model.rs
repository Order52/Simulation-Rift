//! Rift AI's model now also arrives inside signed packs, and is parsed as
//! untrusted bytes. A file of the right size is built around the fuzzed
//! header and weights, so the parser is reached past its size check. Odd
//! inputs append their remaining bytes raw (the section checks); even ones
//! get header numbers in range and well-formed sections made from them
//! (suffix rules, popular sites, a factor table), so whole models are
//! reached. Parsing must never panic, and a model that parses must score
//! any address within its bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_core::urlcanon;
use rift_core::urlmodel::{FEATURE_SCHEMA, MIN_BITS, UrlModel, View};

/// Takes up to `n` bytes from the front of `data`.
fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, rest) = data.split_at(n.min(data.len()));
    *data = rest;
    head
}

fn byte(data: &mut &[u8]) -> u8 {
    take(data, 1).first().copied().unwrap_or(0)
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let well_formed = byte(&mut data) % 2 == 0;
    let mut floats = [0u8; 16];
    floats.copy_from_slice(&{
        let mut f = take(&mut data, 16).to_vec();
        f.resize(16, 0);
        f
    });
    if well_formed {
        let unit = |b: u8| (f32::from(b) + 1.0) / 257.0;
        let (a, b) = (unit(floats[8]), unit(floats[12]));
        let header = [
            unit(floats[0]) * 0.01,
            (f32::from(floats[4]) - 128.0) / 16.0,
            a.min(b),
            a.max(b),
        ];
        for (i, value) in header.iter().enumerate() {
            floats[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    let weights = take(&mut data, 64);
    let mut bytes = b"RIFTURL1".to_vec();
    bytes.extend_from_slice(&FEATURE_SCHEMA.to_le_bytes());
    bytes.extend_from_slice(&MIN_BITS.to_le_bytes());
    bytes.extend_from_slice(&floats);
    let table = 2usize << MIN_BITS;
    if weights.is_empty() {
        bytes.resize(bytes.len() + table, 0);
    } else {
        bytes.extend(weights.iter().cycle().take(table));
    }
    let typed = String::from_utf8_lossy(data).into_owned();
    if well_formed {
        let n = usize::from(byte(&mut data));
        let rules = take(&mut data, n);
        bytes.extend_from_slice(&(rules.len() as u32).to_le_bytes());
        bytes.extend_from_slice(rules);
        let sites = usize::from(byte(&mut data) % 8);
        let mut popular: Vec<u64> = take(&mut data, sites * 8)
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
            .collect();
        popular.sort_unstable();
        popular.dedup();
        bytes.extend_from_slice(&(popular.len() as u32).to_le_bytes());
        for key in popular {
            bytes.extend_from_slice(&key.to_le_bytes());
        }
        let factors = byte(&mut data);
        if factors % 2 == 1 {
            let (k, bits) = (u32::from(factors / 2 % 8 + 1), 10u32);
            bytes.extend_from_slice(&k.to_le_bytes());
            bytes.extend_from_slice(&bits.to_le_bytes());
            bytes.extend_from_slice(&0.01f32.to_le_bytes());
            let values = if data.is_empty() { &[0u8][..] } else { data };
            bytes.extend(values.iter().cycle().take((2 << bits) * k as usize));
        }
    } else {
        bytes.extend_from_slice(data);
    }
    let Ok(model) = UrlModel::parse(&bytes) else {
        return;
    };
    for address in [
        "https://secure-login.example.xyz/verify?account=1",
        "http://192.168.1.1/login",
        "https://www.example.co.uk/",
        &format!("https://{typed}.example/{typed}"),
    ] {
        let Ok(url) = urlcanon::canonicalize(address.as_bytes()) else {
            continue;
        };
        for view in [View::Address, View::HostOnly] {
            let assessment = model.assess(&url, view);
            assert!(assessment.risk <= 99);
            assert!(assessment.signals.len() <= 3);
            let _ = model.abstains(&url);
        }
    }
});
