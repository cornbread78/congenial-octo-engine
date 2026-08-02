use std::fs;
use std::path::Path;
use sha2::{Sha256, Digest};

fn main() {
    println!("Initializing UTXO Scanner with Alpha Root Kernel...");
    
    let path = Path::new("./datadir/kernel_route.dat");
    let key_data = match fs::read(path) {
        Ok(data) => {
            println!("Kernel key loaded successfully for UTXO derivation.");
            data
        }
        Err(e) => {
            println!("Failed to load kernel route: {}", e);
            return;
        }
    };

    println!("Deriving child addresses from path m/4/4/0/0/...");
    for i in 0..3u32 {
        let mut hasher = Sha256::new();
        hasher.update(&key_data);
        hasher.update(&i.to_le_bytes());
        let child_hash = hasher.finalize();
        
        println!("Derived Address Index [{}] -> Hash: {:x?}", i, child_hash);
    }
    
    println!("UTXO scan cycle complete. Ready to query blockchain database.");
}
