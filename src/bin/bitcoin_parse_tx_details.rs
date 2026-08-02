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
    println!("Parsing transactions with Coinbase support...");
    let blocks_path = Path::new("./datadir/blocks");
    
    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains("05673") && name.ends_with("_decrypted.dat") {
                if let Ok(data) = fs::read(entry.path()) {
                    if data.len() > 88 {
                        let mut payload = data[8..].to_vec();
                        let mask: [u8; 4] = [0xfe, 0x28, 0x43, 0xc5];
                        for (i, byte) in payload.iter_mut().enumerate() {
                            *byte ^= mask[i % mask.len()];
                        }
                        
                        let mut pos = 80;
                        let tx_count = match read_varint(&payload, &mut pos) {
                            Some(c) => c,
                            None => {
                                println!("  [ERROR] Failed to read transaction count.");
                                continue;
                            }
                        };
                        
                        println!("Analyzing transactions in {} (Total: {})", name, tx_count);
                        
                        for tx_idx in 0..tx_count.min(5) {
                            let start_pos = pos;
                            if pos + 4 > payload.len() { break; }
                            let tx_version = u32::from_le_bytes([payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]]);
                            pos += 4;
                            
                            // Check for SegWit marker and flag (0x00, 0x01)
                            let mut is_segwit = false;
                            if pos + 2 <= payload.len() && payload[pos] == 0x00 && payload[pos+1] == 0x01 {
                                is_segwit = true;
                                pos += 2;
                            }
                            
                            let in_count = match read_varint(&payload, &mut pos) {
                                Some(c) => c,
                                None => break,
                            };
                            
                            let mut valid_tx = true;
                            for i in 0..in_count {
                                if tx_idx == 0 && i == 0 {
                                    // Coinbase input: 32 bytes prevout hash + 4 bytes index
                                    if pos + 36 > payload.len() { valid_tx = false; break; }
                                    pos += 36;
                                } else {
                                    if pos + 36 > payload.len() { valid_tx = false; break; }
                                    pos += 36;
                                }
                                
                                let script_len = match read_varint(&payload, &mut pos) {
                                    Some(l) => l as usize,
                                    None => { valid_tx = false; break; }
                                };
                                if pos + script_len + 4 > payload.len() { valid_tx = false; break; }
                                pos += script_len + 4; // script + sequence
                            }
                            
                            if !valid_tx { 
                                println!("  [Tx #{}] Failed during input parsing at pos {}", tx_idx, pos);
                                break; 
                            }
                            
                            let out_count = match read_varint(&payload, &mut pos) {
                                Some(c) => c,
                                None => break,
                            };
                            
                            for _ in 0..out_count {
                                if pos + 8 > payload.len() { valid_tx = false; break; }
                                let value = u64::from_le_bytes([
                                    payload[pos], payload[pos+1], payload[pos+2], payload[pos+3],
                                    payload[pos+4], payload[pos+5], payload[pos+6], payload[pos+7]
                                ]);
                                pos += 8;
                                
                                let pk_script_len = match read_varint(&payload, &mut pos) {
                                    Some(l) => l as usize,
                                    None => { valid_tx = false; break; }
                                };
                                if pos + pk_script_len > payload.len() { valid_tx = false; break; }
                                pos += pk_script_len;
                                
                                if tx_idx == 0 {
                                    println!("    -> Coinbase Output Value: {} satoshis ({:.8} BTC)", value, value as f64 / 100_000_000.0);
                                }
                            }
                            
                            if !valid_tx { 
                                println!("  [Tx #{}] Failed during output parsing at pos {}", tx_idx, pos);
                                break; 
                            }
                            
                            // Skip witness data if SegWit
                            if is_segwit {
                                for _ in 0..in_count {
                                    let witness_stack_count = match read_varint(&payload, &mut pos) {
                                        Some(c) => c,
                                        None => { valid_tx = false; break; }
                                    };
                                    for _ in 0..witness_stack_count {
                                        let item_len = match read_varint(&payload, &mut pos) {
                                            Some(l) => l as usize,
                                            None => { valid_tx = false; break; }
                                        };
                                        if pos + item_len > payload.len() { valid_tx = false; break; }
                                        pos += item_len;
                                    }
                                }
                            }
                            
                            if !valid_tx { break; }

                            println!("  [Tx #{}] Version: {}, SegWit: {}, Inputs: {}, Outputs: {}, Bytes parsed: {}", 
                                tx_idx, tx_version, is_segwit, in_count, out_count, pos - start_pos);
                        }
                    }
                }
            }
        }
    }
    println!("\nCoinbase transaction parse complete.");
}
