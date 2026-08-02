use std::fs;
use std::path::Path;

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

fn main() {
    println!("Extracting dynamic key from Record #0 and decoding vault...");
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
                        
                        let mut pos = 80;
                        let record_count = read_varint(&vault_payload, &mut pos).unwrap_or(0);
                        
                        // First pass: extract Record #0 raw ciphertext
                        let mut records = Vec::new();
                        for _ in 0..record_count {
                            if pos >= vault_payload.len() { break; }
                            let record_len = match read_varint(&vault_payload, &mut pos) {
                                Some(l) => l as usize,
                                None => break,
                            };
                            if pos + record_len <= vault_payload.len() {
                                records.push(vault_payload[pos..pos + record_len].to_vec());
                                pos += record_len;
                            } else {
                                break;
                            }
                        }
                        
                        if let Some(rec0) = records.first() {
                            let dynamic_key = &rec0[..rec0.len().min(32)];
                            println!("  [Dynamic Key from Record #0 (first {} bytes)] {:02x?}", dynamic_key.len(), dynamic_key);
                            
                            for (r, rec_data) in records.iter().enumerate() {
                                let mut decoded = rec_data.clone();
                                for (i, byte) in decoded.iter_mut().enumerate() {
                                    *byte ^= dynamic_key[i % dynamic_key.len()];
                                }
                                
                                let text_lossy = String::from_utf8_lossy(&decoded);
                                let printable = text_lossy.chars().filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace()).count();
                                
                                if printable as f32 / decoded.len() as f32 > 0.6 {
                                    println!("  [Decoded Record #{}] Len: {} | Text: {}", r, decoded.len(), text_lossy);
                                } else if r < 10 {
                                    println!("  [Record #{}] Len: {} | Hex: {:02x?}", r, decoded.len(), &decoded[..decoded.len().min(12)]);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!("\nDynamic decoding complete.");
}
