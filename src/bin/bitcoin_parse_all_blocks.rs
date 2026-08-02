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
    println!("Parsing blocks with unmasked length descriptors...");
    let blocks_path = Path::new("./datadir/blocks");
    
    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains("05673") && name.ends_with("_decrypted.dat") {
                if let Ok(data) = fs::read(entry.path()) {
                    println!("\nAnalyzing file: {} ({} bytes)", name, data.len());
                    let mut offset = 0;
                    let mut block_index = 0;
                    
                    let mask: [u8; 4] = [0xfe, 0x28, 0x43, 0xc5];
                    
                    while offset + 8 <= data.len() {
                        let magic = &data[offset..offset+4];
                        
                        // Unmask the 4-byte length descriptor
                        let mut raw_len_bytes = [
                            data[offset+4], data[offset+5], data[offset+6], data[offset+7]
                        ];
                        for (i, byte) in raw_len_bytes.iter_mut().enumerate() {
                            *byte ^= mask[i];
                        }
                        let length = u32::from_le_bytes(raw_len_bytes) as usize;
                        
                        if magic != [0xf9, 0xbe, 0xb4, 0xd9] {
                            offset += 1;
                            continue;
                        }
                        
                        if offset + 8 + length > data.len() {
                            println!("  [Note] Reached end of valid stream buffer at offset {}", offset);
                            break;
                        }
                        
                        block_index += 1;
                        let mut payload = data[offset+8..offset+8+length].to_vec();
                        
                        for (i, byte) in payload.iter_mut().enumerate() {
                            *byte ^= mask[i % mask.len()];
                        }
                        
                        if payload.len() >= 80 {
                            let version = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                            let time = u32::from_le_bytes([payload[68], payload[69], payload[70], payload[71]]);
                            
                            let mut pos = 80;
                            if let Some(tx_count) = read_varint(&payload, &mut pos) {
                                println!("  [Block #{}] Offset: {}, Length: {} bytes, Version: 0x{:08x}, Timestamp: {}, Transactions: {}", 
                                    block_index, offset, length, version, time, tx_count);
                            }
                        }
                        
                        offset += 8 + length;
                    }
                    println!("Total blocks successfully parsed in {}: {}", name, block_index);
                }
            }
        }
    }
    println!("\nStream parse complete.");
}
