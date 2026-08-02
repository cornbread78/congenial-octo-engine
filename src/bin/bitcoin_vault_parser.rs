use std::fs;
use std::path::Path;

fn main() {
    println!("Unsealing Alpha Root Kernel vault archive...");
    let blocks_path = Path::new("./datadir/blocks");
    
    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "blk05673_decrypted.dat" {
                if let Ok(data) = fs::read(entry.path()) {
                    println!("\nVault File: {} ({} bytes)", name, data.len());
                    
                    if data.len() > 8 {
                        let container_magic = &data[..4];
                        let mut vault_header_len = [data[4], data[5], data[6], data[7]];
                        
                        // Apply Alpha Root Kernel mask to vault header descriptor
                        let mask: [u8; 4] = [0xfe, 0x28, 0x43, 0xc5];
                        for (i, byte) in vault_header_len.iter_mut().enumerate() {
                            *byte ^= mask[i];
                        }
                        
                        let unmasked_len = u32::from_le_bytes(vault_header_len);
                        println!("  Container Magic: {:02x?}", container_magic);
                        println!("  Vault Partition Size Descriptor: {} bytes", unmasked_len);
                        
                        // Extract vault payload stream
                        let mut vault_payload = data[8..].to_vec();
                        for (i, byte) in vault_payload.iter_mut().enumerate() {
                            *byte ^= mask[i % mask.len()];
                        }
                        
                        println!("  Vault unsealed successfully. Payload length: {} bytes", vault_payload.len());
                        
                        // Inspect vault entry markers or inner descriptors
                        if vault_payload.len() >= 64 {
                            println!("  Vault root signature / header bytes: {:02x?}", &vault_payload[..32]);
                        }
                    }
                }
            }
        }
    }
    println!("\nVault parsing complete.");
}
