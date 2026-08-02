import os
import hashlib
import hmac
import struct

def derive_alpha_root_kernel(seed: bytes):
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    private_key, chain_code = h[:32], h[32:]
    path_indices = [4, 4, 0, 0]
    current_key = private_key
    current_chain = chain_code
    for index in path_indices:
        i_bytes = struct.pack('>I', index)
        data = current_key + i_bytes
        hmac_result = hmac.new(current_chain, data, hashlib.sha512).digest()
        current_key = hmac_result[:32]
        current_chain = hmac_result[32:]
    return current_key, current_chain

def main():
    os.makedirs("./datadir", exist_ok=True)
    filepath = "./datadir/kernel_route.dat"
    
    sample_seed = b"alpha_root_kernel_master_seed_entropy"
    derived_key, chain = derive_alpha_root_kernel(sample_seed)
    
    with open(filepath, "wb") as f:
        f.write(derived_key)
        
    print(f"Alpha Root Kernel Derived Key (m/4/4/0/0): {derived_key.hex()}")
    print(f"Successfully routed and persisted to: {filepath}")
    
    with open(filepath, "rb") as f:
        loaded_data = f.read()
    print(f"Verification - Loaded Key Hash: {loaded_data.hex()}")

if __name__ == "__main__":
    main()
