VECTOR = "04/04/00/00"
segments = [int(p) for p in VECTOR.split('/')]
offset = (segments[0] << 24) ^ (segments[1] << 16) ^ (segments[2] << 8) ^ segments[3]

print(f"[+] Loading Alpha Root Kernel Vector: {VECTOR}")
print(f"[+] Segments: {segments}")
print(f"[+] Computed Traversal Offset: {offset}")
