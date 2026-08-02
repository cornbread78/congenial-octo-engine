use std::fs;
use std::path::Path;

fn main() {
    println!("Initializing Safe Alpha Kernel Block Deserializer...");

    let blocks_path = Path::new("./datadir/blocks");
    if !blocks_path.exists() {
        println!("Blocks directory not found.");
        return;
    }

    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();

            if path.is_file() && (name.contains("0567") && name.ends_with(".dat")) {
                println!("\nAnalyzing file: {}", name);
                if let Ok(metadata) = entry.metadata() {
                    println!("  File size: {} bytes", metadata.len());
                }

                if let Ok(data) = fs::read(&path) {
                    if data.len() >= 8 {
                        let magic = &data[..4];
                        let length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                        println!("  Magic bytes: {:02x?}", magic);
                        println!("  First block payload length header: {} bytes", length);
                    } else {
                        println!("  File is too small to contain standard block headers.");
                    }
                }
            }
        }
    }
    println!("\nDeserialization scan complete.");
}
