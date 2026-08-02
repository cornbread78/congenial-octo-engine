use std::fs;
use std::path::Path;

fn read_varint(data: &[u8], pos: &mut usize) -> u64 {
    let flag = data[*pos];
    *pos += 1;
    match flag {
        0xff => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[*pos..*pos+8]);
            *pos += 8;
            u64::from_le_bytes(bytes)
        }
        0xfe => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&data[*pos..*pos+4]);
            *pos += 4;
            u32::from_le_bytes(bytes) as u64
        }
        0xfd => {
            let mut bytes = [0u8; 2];
            bytes.copy_from_slice(&data[*pos..*pos+2]);
            *pos += 2;
            u16::from_le_bytes(bytes) as u64
        }
        _ => flag as u64,
    }
}

fn main() {
    println!("Parsing unmasked block transactions...");
    let blocks_path = Path::new("./datadir/blocks");
    
    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains("0567") && name.ends_with("blk05673_decrypted.dat") {
                if let Ok(data) = fs::read(entry.path()) {
                    if data.len() > 88 {
                        let mut payload = data[8..].to_vec();
                        
                        let mask: [u8; 4] = [0xfe, 0x28, 0x43, 0xc5];
                        for (i, byte) in payload.iter_mut().enumerate() {
                            *byte ^= mask[i % mask.len()];
                        }
                        
                        let mut pos = 80;
                        if pos < payload.len() {
                            let tx_count = read_varint(&payload, &mut pos);
                            println!("  [SUCCESS] Unmasked block payload parsed.");
                            println!("  File: {}", name);
                            println!("  Total transactions in block: {}", tx_count);
                        }
                    }
                }
            }
        }
    }
    println!("\nTransaction parsing scan complete.");
}
