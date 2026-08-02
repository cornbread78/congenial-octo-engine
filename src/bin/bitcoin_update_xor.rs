use std::fs;
use std::path::Path;

fn main() {
    println!("Updating xor.dat with Alpha Kernel translation key...");
    // Key derived to transform [d9, b4, 00, 0d] -> [f9, be, b4, d9]
    let new_key: [u8; 8] = [0x20, 0x0a, 0xb4, 0xd4, 0x20, 0x0a, 0xb4, 0xd4];
    
    if fs::write("./datadir/blocks/xor.dat", &new_key).is_ok() {
        println!("  [SUCCESS] xor.dat successfully updated.");
    } else {
        println!("  [ERROR] Failed to write to xor.dat");
    }
}
