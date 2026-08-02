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
    println!("Analyzing internal repeating patterns in vault records...");
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
                        
                        // Candidate key derived from recurring pattern: [0x8c, 0x35, 0x2a, 0x96, 0xf0, 0x19, 0x80, 0x60]
                        let pattern_key = [0x8c, 0x35, 0x2a, 0x96, 0xf0, 0x19, 0x80, 0x60];
                        
                        let mut decoded_count = 0;
                        for r in 0..record_count {
                            if pos >= vault_payload.len() { break; }
                            let record_len = match read_varint(&vault_payload, &mut pos) {
                                Some(l) => l as usize,
                                None => break,
                            };
                            
                            if pos + record_len <= vault_payload.len() {
                                let mut record_data = vault_payload[pos..pos + record_len].to_vec();
                                
                                for (i, byte) in record_data.iter_mut().enumerate() {
                                    *byte ^= pattern_key[i % pattern_key.len()];
                                }
                                
                                let text_lossy = String::from_utf8_lossy(&record_data);
                                let printable = text_lossy.chars().filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace()).count();
                                
                                if printable as f32 / record_data.len() as f32 > 0.65 {
                                    println!("  [Decoded Record #{}] (Len: {}) Text: {}", r, record_len, text_lossy);
                                    decoded_count += 1;
                                } else if r < 5 {
                                    println!("  [Record #{}] (Len: {}) Decoded Hex: {:02x?}", r, record_len, &record_data[..record_data.len().min(16)]);
                                }
                                
                                pos += record_len;
                            } else {
                                break;
                            }
                        }
                        println!("\nPattern analysis complete. Successfully decoded readable records: {}", decoded_count);
                    }
                }
            }
        }
    }
}
