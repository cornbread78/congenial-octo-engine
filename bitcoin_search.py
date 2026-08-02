import os
import hmac
import hashlib

def rv(d, p):
    if p >= len(d): return None, p
    f = d[p]; p += 1
    if f == 0xff: return int.from_bytes(d[p:p+8], "le"), p+8
    if f == 0xfe: return int.from_bytes(d[p:p+4], "le"), p+4
    if f == 0xfd: return int.from_bytes(d[p:p+2], "le"), p+2
    return f, p

d = open("./datadir/blocks/blk05673_decrypted.dat", "rb").read()
mask = b"\xfe\x28\x43\xc5"
pl = bytearray(d[8:])
for i in range(len(pl)): pl[i] ^= mask[i%4]

seeds = [
    b"open sesame:Stuck in the middle with me:close sesame",
    b"open sesame:stuck in the middle with me:close sesame",
    b"open sesame:Stuck in the Middle with Me:close sesame",
    b"open sesame:Middle:close sesame",
    b"open sesame:middle:close sesame",
    b"04/04/00/00:open sesame:Stuck in the middle with me:close sesame"
]

for seed in seeds:
    key = hmac.new(b"Alpha Root Kernel", seed, hashlib.sha256).digest()
    pos = 80
    count, pos = rv(pl, pos)
    readable = 0
    for r in range(count or 0):
        l, pos = rv(pl, pos)
        if l is None or pos + l > len(pl): break
        rec = bytearray(pl[pos:pos+l])
        for i in range(len(rec)): rec[i] ^= key[i % len(key)]
        
        txt = "".join([chr(b) if 32 <= b < 127 else "." for b in rec])
        printable_ratio = sum(1 for c in txt if c != '.') / max(len(txt), 1)
        
        if printable_ratio > 0.4:
            print(f"[{seed[12:30].decode('utf-8', errors='ignore')}] Rec #{r} ({l} bytes): {txt[:80]}")
            readable += 1
        pos += l
    print(f"Seed tested: {seed[:35]}... | Readable records found: {readable}\n")
