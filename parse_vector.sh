#!/bin/bash

# Target Vector configuration
VECTOR="04/04/00/00"

echo "[+] Loading Alpha Root Kernel Vector: $VECTOR"

# Split path segments using IFS
IFS='/' read -r s1 s2 s3 s4 <<< "$VECTOR"

# Convert hex/decimal string components to integers for bitwise operations
val1=$((10#$s1))
val2=$((10#$s2))
val3=$((10#$s3))
val4=$((10#$s4))

# Compute traversal offset matching the python/rust logic
offset=$(( (val1 << 24) ^ (val2 << 16) ^ (val3 << 8) ^ val4 ))

echo "[+] Segments: [$val1, $val2, $val3, $val4]"
echo "[+] Computed Traversal Offset: $offset"
