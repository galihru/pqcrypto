import math
import json
import os

from pqcrypto import keygen, encrypt, decrypt

p = 10007
a = 5
P0 = (1, 0)

def max_block_size(p: int) -> int:
    """
    Compute B = floor((bit_length(p) - 1) / 8),
    so that any B-byte big-endian integer < p.
    """
    bit_len = p.bit_length()
    return (bit_len - 1) // 8

def file_to_int_blocks(filepath: str, p: int) -> list[int]:
    """
    1. Read the entire file as bytes.
    2. Split it into chunks of length B = max_block_size(p).
    3. Convert each chunk to an integer with int.from_bytes(..., 'big').
    4. Assert each integer < p.
    """
    with open(filepath, "rb") as f:
        raw = f.read()

    B = max_block_size(p)
    if B < 1:
        raise ValueError("Prime p is too small; block size < 1 byte.")

    blocks = []
    n_blocks = math.ceil(len(raw) / B)
    for i in range(n_blocks):
        start = i * B
        end = start + B
        chunk = raw[start:end]
        m_int = int.from_bytes(chunk, byteorder="big")
        if m_int >= p:
            raise ValueError(f"Block integer ≥ p! Check block size. (block index {i})")
        blocks.append(m_int)

    return blocks

def encrypt_js_file(js_path: str, output_json: str, p: int, a: int, P0: tuple[int,int]) -> None:
    """
    1) Generate (k, Q) via keygen.
    2) Read js_path, split into integer blocks.
    3) Encrypt each block → (C1, C2, r).
    4) Write p, a, P0, k, Q, blocks into output_json.
    """
    # Generate keypair
    k, Q = keygen(p, a, P0)

    # Split file into int blocks
    m_blocks = file_to_int_blocks(js_path, p)

    ciphertext_blocks = []
    for m_int in m_blocks:
        # encrypt expects exactly 6 args: (m_int, public_Q, private_k, p, a, P0)
        C1, C2, r = encrypt(m_int, Q, k, p, a, P0)
        ciphertext_blocks.append({
            "C1": [C1[0], C1[1]],
            "C2": [C2[0], C2[1]],
            "r": r
        })

    # Bundle into JSON
    result = {
        "p": p,
        "a": a,
        "P0": [P0[0], P0[1]],
        "k": k,
        "Q": [Q[0], Q[1]],
        "blocks": ciphertext_blocks
    }
    with open(output_json, "w", encoding="utf-8") as fout:
        json.dump(result, fout, indent=2)
    print(f"✅ File ciphertext written to '{output_json}'.")

if __name__ == "__main__":
    repo_root = os.getcwd()
    js_path = os.path.join(repo_root, "script.min.js")
    output_json = os.path.join(repo_root, "script.min.json")

    # 1) Encrypt → script.min.json
    encrypt_js_file(js_path, output_json, p, a, P0)

    # 2) Immediately verify by decrypting
    with open(output_json, "r", encoding="utf-8") as fin:
        loaded = json.load(fin)

    def max_block_size_int(p_val: int) -> int:
        return (p_val.bit_length() - 1) // 8

    decrypted_int_blocks = []
    for blk in loaded["blocks"]:
        x1, y1 = blk["C1"]
        x2, y2 = blk["C2"]
        r_val = blk["r"]
        # decrypt expects: (C1_tuple, C2_tuple, private_k, r, a, p)
        m_int = decrypt((x1, y1), (x2, y2),
                        loaded["k"], r_val,
                        loaded["a"], loaded["p"])
        decrypted_int_blocks.append(m_int)

    # Reassemble into raw bytes
    B = max_block_size_int(loaded["p"])
    all_bytes = bytearray()
    for m_int in decrypted_int_blocks:
        if m_int < 0 or m_int >= loaded["p"]:
            raise ValueError(f"Decrypted integer out of range: {m_int}")
        if m_int == 0:
            chunk = b"\x00"
        else:
            byte_len = math.ceil(m_int.bit_length() / 8)
            chunk = m_int.to_bytes(byte_len, byteorder="big")
        if len(chunk) > B:
            raise ValueError(f"Block at integer {m_int} is longer than B bytes")
        # Pad on the left with zeros to length B
        chunk = chunk.rjust(B, b"\x00")
        all_bytes.extend(chunk)

    # Compare to the original
    with open(js_path, "rb") as fin_js:
        original_bytes = fin_js.read()
    decrypted_bytes = bytes(all_bytes[: len(original_bytes)])
    if decrypted_bytes != original_bytes:
        raise RuntimeError("❌ Decryption mismatch: decrypted content != original JS")
    print("✅ Decryption successful: plaintext matches script.min.js exactly.")
