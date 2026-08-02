import os

patched_count = 0

for root, dirs, files in os.walk("."):
    for file in files:
        if file.endswith(".py") and file != "patch_decode.py":
            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            if "bech32.Encoding" in content:
                updated = content.replace("bech32.Encoding.BECH32M", "1")
                updated = updated.replace("bech32.Encoding.BECH32", "0")

                if updated != content:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(updated)
                    print(f"[+] Patched {filepath} successfully.")
                    patched_count += 1

if patched_count == 0:
    print("[-] No files containing 'bech32.Encoding' were found to patch.")
else:
    print(f"[+] Total files patched: {patched_count}")
