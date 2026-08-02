use std::fs;
use std::path::Path;

fn main() {
    println!("Inspecting repository files...");
    if let Ok(entries) = fs::read_dir("src") {
        for entry in entries.flatten() {
            println!("  src/{}", entry.file_name().to_string_lossy());
        }
    }
    if let Ok(entries) = fs::read_dir("src/bin") {
        for entry in entries.flatten() {
            println!("  src/bin/{}", entry.file_name().to_string_lossy());
        }
    }
}
