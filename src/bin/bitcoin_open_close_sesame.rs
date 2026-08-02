use std::fs;
use std::path::Path;
use sha2::{Sha256, Digest};

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hashed = Sha256::digest(key);
        k[..32].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let result = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos >= data.len() { return None; }
    let flag = data[*pos];
    *pos += 1;
    match flag {
        0xff => {
            if *pos + 8 > data.len() { return None; }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[*pos..*pos+8]);
            *pos += 8;
            Some(u64::from_le_bytes(bytes))
        }
        0xfe => {
            if *pos + 4 > data.len() { return None; }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&data[*pos..*pos+4]);
            *pos += 4;
            Some(u32::from_le_bytes(bytes) as u64)
        }
        0xfd => {
            if *pos + 2 > data.len() { return None; }
            let mut bytes = [0u8; 2];
            bytes.copy_from_slice(&data[*pos..*pos+2]);
            *pos += 2;
            Some(u16::from_le_bytes(bytes) as u64)
        }
        _ => Some(flag as u64),
    }
}

fn test_mode(vault_payload: &[u8], key: &[u8], label: &str) {
    let mut pos = 80;
    let record_count = read_varint(vault_payload, &mut pos).unwrap_or(0);
    let mut readable_count = 0;
    for r in 0..record_count {
        if pos >= vault_payload.len() { break; }
        let record_len = match read_varint(vault_payload, &mut pos) {
            Some(l) => l as usize,
            None => break,
        };
        if pos + record_len <= vault_payload.len() {
            let mut record_data = vault_payload[pos..pos + record_len].to_vec();
            for (i, byte) in record_data.iter_mut().enumerate() {
                *byte ^= key[i % key.len()];
            }
            let text_lossy = String::from_utf8_lossy(&record_data);
            let printable = text_lossy.chars().filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace()).count();
            if printable as f32 / record_data.len() as f32 > 0.65 {
                println!("  [{}] Decoded Record #{}: {}", label, r, text_lossy);
                readable_count += 1;
            }
            pos += record_len;
        } else {
            break;
        }
    }
    println!("  [{}] Readable records: {}", label, readable_count);
}

fn main() {
    println!("Testing 'open sesame' + 'close sesame' vault unsealing combinations...");
    let blocks_path = Path::new("./datadir/blocks");
    
    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "blk05673_decrypted.dat" {
                if let Ok(data) = fs::read(entry.path()) {
                    if data.len() > 88 {
                        let mask: [u8; 4] = [0xfe, 0x28, 0x43, 0xc5];
                        let mut vault_payload = data[8..].to_vec();
                        for (i, byte) in vault_payload.iter_mut().enumerate() {
                            *byte ^= mask[i % mask.len()];
                        }
                        
                        // 1. Direct concatenation of open and close sesame keys
                        let mut combined_key = b"open sesame".to_vec();
                        combined_key.extend_from_slice(b"close sesame");
                        test_mode(&vault_payload, &combined_key, "Open+Close Concatenated");
                        
                        // 2. HMAC-SHA256 derived key using Alpha Root Kernel and "open sesame:close sesame"
                        let hmac_key1 = hmac_sha256(b"Alpha Root Kernel", b"open sesame:close sesame");
                        test_mode(&vault_payload, &hmac_key1, "Alpha Root Kernel + open:close");
                        
                        // 3. Dual-pass XOR (open sesame, then close sesame)
                        let mut pos = 80;
                        let record_count = read_varint(&vault_payload, &mut pos).unwrap_or(0);
                        let mut dual_readable = 0;
                        for r in 0..record_count {
                            if pos >= vault_payload.len() { break; }
                            let record_len = match read_varint(&vault_payload, &mut pos) {
                                Some(l) => l as usize,
                                None => break,
                            };
                            if pos + record_len <= vault_payload.len() {
                                let mut record_data = vault_payload[pos..pos + record_len].to_vec();
                                let open_key = b"open sesame";
                                let close_key = b"close sesame";
                                for (i, byte) in record_data.iter_mut().enumerate() {
                                    *byte ^= open_key[i % open_key.len()];
                                    *byte ^= close_key[i % close_key.len()];
                                }
                                let text_lossy = String::from_utf8_lossy(&record_data);
                                let printable = text_lossy.chars().filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace()).count();
                                if printable as f32 / record_data.len() as f32 > 0.65 {
                                    println!("  [Dual-Pass XOR] Decoded Record #{}: {}", r, text_lossy);
                                    dual_readable += 1;
                                }
                                pos += record_len;
                            } else {
                                break;
                            }
                        }
                        println!("  [Dual-Pass XOR] Readable records: {}", dual_readable);
                    }
                }
            }
        }
    }
}
