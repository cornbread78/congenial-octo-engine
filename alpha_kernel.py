import os

def load_and_route_kernel():
    filepath = "./datadir/kernel_route.dat"
    
    if not os.path.exists(filepath):
        print("Error: Kernel route file not found.")
        return None
        
    with open(filepath, "rb") as f:
        key_data = f.read()
        
    print(f"Successfully loaded Alpha Root Kernel Key from {filepath}")
    print(f"Key Hash (Hex): {key_data.hex()}")
    return key_data

if __name__ == "__main__":
    active_key = load_and_route_kernel()
    # Ready for integration with cargo run --bin or block modules

