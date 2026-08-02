use std::fs;
use std::path::Path;

fn main() {
    println!("Initializing Alpha Kernel XOR Decryption Pipeline...");

    let xor_path = Path::new("./datadir/blocks/xor.dat");
    if !xor_path.exists() {
        println!("xor.dat configuration layer not found.");
        return;
    }

    let xor_key = match fs::read(xor_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Failed to read xor.dat: {}", e);
            return;
        }
    };

    if xor_key.is_empty() {
        println!("xor.dat is empty.");
        return;
    }

    let blocks_path = Path::new("./datadir/blocks");
    if let Ok(entries) = fs::read_dir(blocks_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();

            if path.is_file() && name.contains("0567") && name.ends_with(".dat") && !name.contains("decrypted") {
                println!("\nDecrypting file: {}", name);
                if let Ok(data) = fs::read(&path) {
                    let mut decrypted_data = data.clone();
                    for (i, byte) in decrypted_data.iter_mut().enumerate() {
                        let key_byte = xor_key[i % xor_key.len()];
                        *byte ^= key_byte;
                    }

                    let new_name = format!("./datadir/blocks/{}_decrypted.dat", name.trim_end_matches(".dat"));
                    if fs::write(&new_name, &decrypted_data).is_ok() {
                        println!("  [SUCCESS] Saved decrypted stream to: {}", new_name);
                        if decrypted_data.len() >= 4 {
                            println!("  New magic bytes: {:02x?}", &decrypted_data[..4]);
                        }
                    }
                }
            }
        }
    }
    println!("\nDecryption pipeline complete.");
}
