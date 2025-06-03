import math
import json
import os

from pqcrypto import keygen, encrypt

p = 10007
a = 5
P0 = (1, 0)

def max_block_size(p: int) -> int:
    bit_len = p.bit_length()
    return (bit_len - 1) // 8

def file_to_int_blocks(filepath: str, p: int) -> list[int]:
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

def encrypt_js_file(js_relative_path: str, output_json: str, p: int, a: int, P0: tuple[int,int]) -> None:
    k, Q = keygen(p, a, P0)

    m_blocks = file_to_int_blocks(js_relative_path, p)

    ciphertext_blocks = []
    for m_int in m_blocks:
        C1, C2, r = encrypt(m_int, Q, k, p, a, P0)
        ciphertext_blocks.append({
            "C1": [C1[0], C1[1]],
            "C2": [C2[0], C2[1]],
            "r": r
        })

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
    print(f"File ciphertext written to '{output_json}'.")

if __name__ == "__main__":
    repo_root = os.getcwd()
    js_path = os.path.join(repo_root, "script.min.js")
    output_json = os.path.join(repo_root, "script.min.json")

    encrypt_js_file(js_path, output_json, p, a, P0)

    with open(output_json, "r", encoding="utf-8") as fin:
        loaded = json.load(fin)

    def max_block_size_int(p: int) -> int:
        return (p.bit_length() - 1) // 8

    decrypted_int_blocks = []
    for blk in loaded["blocks"]:
        x1, y1 = blk["C1"]
        x2, y2 = blk["C2"]
        r_val = blk["r"]
        m_int = encrypt.__self__.decrypt((x1, y1), (x2, y2),
                                         loaded["k"], r_val,
                                         loaded["a"], loaded["p"])
        decrypted_int_blocks.append(m_int)

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
        chunk = chunk.rjust(B, b"\x00")
        all_bytes.extend(chunk)

    with open(js_path, "rb") as fin_js:
        original_bytes = fin_js.read()
    decrypted_bytes = bytes(all_bytes[: len(original_bytes)])
    if decrypted_bytes != original_bytes:
        raise RuntimeError("❌ Decryption mismatch: decrypted content != original JS")
    print("✅ Decryption successful: plaintext matches script.min.js exactly.")
