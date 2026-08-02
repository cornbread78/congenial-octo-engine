use std::fs;
use std::path::Path;

fn main() {
    println!("Parsing Alpha Root Kernel vault anchor header...");
    let blocks_path = Path::new("./datadir/blocks");
    
    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "blk05673_decrypted.dat" {
                if let Ok(data) = fs::read(entry.path()) {
                    if data.len() > 8 {
                        let mask: [u8; 4] = [0xfe, 0x28, 0x43, 0xc5];
                        let mut vault_payload = data[8..].to_vec();
                        for (i, byte) in vault_payload.iter_mut().enumerate() {
                            *byte ^= mask[i % mask.len()];
                        }
                        
                        if vault_payload.len() >= 80 {
                            let version = u32::from_le_bytes([vault_payload[0], vault_payload[1], vault_payload[2], vault_payload[3]]);
                            let anchor_hash = &vault_payload[4..36];
                            let root_hash = &vault_payload[36..68];
                            let timestamp = u32::from_le_bytes([vault_payload[68], vault_payload[69], vault_payload[70], vault_payload[71]]);
                            let attributes = u32::from_le_bytes([vault_payload[72], vault_payload[73], vault_payload[74], vault_payload[75]]);
                            let nonce = u32::from_le_bytes([vault_payload[76], vault_payload[77], vault_payload[78], vault_payload[79]]);
                            
                            println!("\n=== Alpha Root Kernel Vault Header ===");
                            println!("  Version: 0x{:08x}", version);
                            println!("  Anchor Hash: {:02x?}", anchor_hash);
                            println!("  Root Hash: {:02x?}", root_hash);
                            println!("  Timestamp: {} (0x{:08x})", timestamp, timestamp);
                            println!("  Attributes: 0x{:08x}", attributes);
                            println!("  Nonce: 0x{:08x}", nonce);
                        }
                    }
                }
            }
        }
    }
    println!("\nVault header parse complete.");
}
