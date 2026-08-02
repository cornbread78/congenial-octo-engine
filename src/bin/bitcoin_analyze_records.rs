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
    println!("Analyzing vault record signatures and structures...");
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
                        
                        let mut type_32_count = 0;
                        let mut type_33_count = 0;
                        let mut type_64_count = 0;
                        let mut other_count = 0;
                        
                        for r in 0..record_count {
                            if pos >= vault_payload.len() { break; }
                            let record_len = match read_varint(&vault_payload, &mut pos) {
                                Some(l) => l as usize,
                                None => break,
                            };
                            
                            if pos + record_len <= vault_payload.len() {
                                let record_data = &vault_payload[pos..pos + record_len];
                                
                                match record_len {
                                    32 => type_32_count += 1,
                                    33 => type_33_count += 1,
                                    64 => type_64_count += 1,
                                    _ => other_count += 1,
                                }
                                
                                // Print first few bytes and structure analysis for select records
                                if r < 10 {
                                    let first_byte = record_data.first().copied().unwrap_or(0);
                                    println!("  [Record #{}] Len: {:3} | First Byte: 0x{:02x} | Tag/Prefix: {:02x?}", 
                                        r, record_len, first_byte, &record_data[..record_data.len().min(4)]);
                                }
                                
                                pos += record_len;
                            } else {
                                break;
                            }
                        }
                        
                        println!("\n=== Structural Breakdown ===");
                        println!("  32-byte records (Hashes/Keys): {}", type_32_count);
                        println!("  33-byte records (Compressed PubKeys): {}", type_33_count);
                        println!("  64-byte records (Signatures): {}", type_64_count);
                        println!("  Variable/Other size records: {}", other_count);
                    }
                }
            }
        }
    }
    println!("\nRecord structure analysis complete.");
}
