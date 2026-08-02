use std::fs;
use std::path::Path;

fn main() {
    let xor_path = Path::new("./datadir/blocks/xor.dat");
    if let Ok(data) = fs::read(xor_path) {
        println!("xor.dat size: {} bytes", data.len());
        if data.len() >= 16 {
            println!("First 16 bytes of xor.dat: {:02x?}", &data[..16]);
        } else {
            println!("xor.dat contents: {:02x?}", data);
        }
    } else {
        println!("Could not read xor.dat");
    }
}
