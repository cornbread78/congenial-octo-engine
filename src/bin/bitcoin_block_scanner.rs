use std::fs;
use std::path::Path;

fn main() {
    println!("Initializing Alpha Kernel Clean & Purge Utility...");

    let blocks_path = Path::new("./datadir/blocks");
    if !blocks_path.exists() {
        println!("Blocks directory not found.");
        return;
    }

    let mut kept_count = 0;
    let mut removed_count = 0;
    let mut freed_bytes = 0;

    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            
            if path.is_file() {
                let is_critical = name.contains("0567") 
                    || name == "xor.dat" 
                    || name == ".lock"
                    || name.contains("unlocked");

                if is_critical {
                    println!("  [SAVED] {}", name);
                    kept_count += 1;
                } else {
                    if let Ok(metadata) = entry.metadata() {
                        freed_bytes += metadata.len();
                    }
                    if fs::remove_file(&path).is_ok() {
                        println!("  [REMOVED] {}", name);
                        removed_count += 1;
                    }
                }
            }
        }
    }

    println!("--------------------------------------------------");
    println!("Cleanup Complete.");
    println!("  Files Kept: {}", kept_count);
    println!("  Files Removed: {}", removed_count);
    println!("  Storage Freed: {} bytes", freed_bytes);
    println!("--------------------------------------------------");
}
