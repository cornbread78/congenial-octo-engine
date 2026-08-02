use std::fs;
use std::path::Path;

fn main() {
    println!("Running secondary Alpha Kernel stream transform...");
    let blocks_path = Path::new("./datadir/blocks");
    
    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains("0567") && name.ends_with("blk05673_decrypted.dat") {
                if let Ok(data) = fs::read(entry.path()) {
                    println!("\nTarget file: {}", name);
                    if data.len() > 8 {
                        let mut payload = data[8..].to_vec();
                        
                        // Apply secondary stream mask pattern to align with standard block headers
                        let mask: [u8; 4] = [0xd5, 0xcb, 0x94, 0xd4];
                        for (i, byte) in payload.iter_mut().take(64).enumerate() {
                            *byte ^= mask[i % mask.len()];
                        }
                        
                        println!("  Transformed first 32 bytes: {:02x?}", &payload[..32]);
                    }
                }
            }
        }
    }
    println!("\nStream transform test complete.");
}
