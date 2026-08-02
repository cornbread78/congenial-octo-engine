use std::fs;
use std::path::Path;

fn main() {
    println!("Applying final precision mask [0xfe, 0x28, 0x43, 0xc5]...");
    let blocks_path = Path::new("./datadir/blocks");
    
    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains("0567") && name.ends_with("blk05673_decrypted.dat") {
                if let Ok(data) = fs::read(entry.path()) {
                    if data.len() >= 88 {
                        let mut header = data[8..88].to_vec();
                        
                        let mask: [u8; 4] = [0xfe, 0x28, 0x43, 0xc5];
                        for (i, byte) in header.iter_mut().enumerate() {
                            *byte ^= mask[i % mask.len()];
                        }
                        
                        let version = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
                        let time = u32::from_le_bytes([header[68], header[69], header[70], header[71]]);
                        let nonce = u32::from_le_bytes([header[76], header[77], header[78], header[79]]);
                        
                        println!("\n  --- Fully Aligned Block Header ---");
                        println!("    Version: 0x{:08x} ({})", version, version);
                        println!("    Timestamp: {}", time);
                        println!("    Nonce: 0x{:08x}", nonce);
                        println!("    First 4 bytes: {:02x?}", &header[..4]);
                    }
                }
            }
        }
    }
    println!("\nHeader alignment complete.");
}
