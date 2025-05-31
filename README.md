# pqcrypto

<img src="https://github.com/4211421036/pqcrypto/blob/main/logo.png" />

**Post-Quantum Lemniscate-AGM Isogeny (LAI) Encryption**

A Python package providing a reference implementation of the Lemniscate-AGM Isogeny (LAI) encryption scheme. LAI is a promising post-quantum cryptosystem based on isogenies of elliptic curves over lemniscate lattices, offering resistance against quantum-capable adversaries.

---

## Project Overview

This library implements the core mathematical primitives and high-level API of the LAI scheme, including:

* **Key Generation**: Derivation of a private scalar and corresponding public point via binary exponentiation of the LAI transformation.
* **Encryption**: Secure encryption of integer messages modulo a prime.
* **Decryption**: Accurate recovery of plaintext via inverse transform.

The code is annotated with direct correspondence to the mathematical definitions and pseudocode, making it suitable for research, educational use, and further development.

---

## Mathematical Formulation

### 1. Hash-Based Seed Function

Define:

$$
H(x, y, s) \;=\; \mathrm{SHA256}\bigl(x \,\|\, y \,\|\, s\bigr) \bmod p
$$

where \$x,y,s \in \mathbb{Z}\_p\$ and \$|\$ denotes byte-string concatenation.

### 2. Modular Square Root (Tonelli–Shanks)

Compute \$z = \sqrt{a} \bmod p\$ for prime \$p\$:

* If \$p \equiv 3 \pmod{4}\$:
  $z \;=\; a^{\frac{p+1}{4}} \bmod p$
* Otherwise, use the full Tonelli–Shanks algorithm for general primes.

### 3. LAI Transformation \$T\$

Given a point \$(x,y) \in \mathbb{F}\_p^2\$, parameter \$a\$, and seed index \$s\$, define:

$$
\begin{aligned}
    h &= H(x,y,s), \[4pt]
    x' &= \frac{x + a + h}{2} \bmod p, \[4pt]
    y' &= \sqrt{x \, y + h} \bmod p.
\end{aligned}
$$

Thus,

$T\bigl((x,y), s; a, p\bigr) = (\,x', y').$

### 4. Binary Exponentiation of \$T\$

To compute \$T^k(P\_0)\$ efficiently, use exponentiation by squaring:

```text
function pow_T(P, k):
    result ← P
    base   ← P
    s      ← 1
    while k > 0:
        if (k mod 2) == 1:
            result ← T(result, s)
        base ← T(base, s)
        k    ← k >> 1
        s    ← s + 1
    return result
```

### 5. API Algorithms

**Key Generation**

```text
function keygen(p, a, P0):
    k ← random integer in [1, p−1]
    Q ← pow_T(P0, k)
    return (k, Q)
```

**Encryption**

```text
function encrypt(m, Q, p, a, P0):
    r  ← random integer in [1, p−1]
    C1 ← pow_T(P0, r)
    Sr ← pow_T(Q, r)
    M  ← (m mod p, 0)
    C2 ← ( (M.x + Sr.x) mod p,
            (M.y + Sr.y) mod p )
    return (C1, C2)
```

**Decryption**

```text
function decrypt(C1, C2, k, a, p):
    S   ← pow_T(C1, k)
    M.x ← (C2.x − S.x) mod p
    return M.x
```

---

## Features

1. **Pure Python** implementation: no external dependencies for core routines (uses `hashlib` & `secrets`).
2. **Mathematically Annotated**: formulas and pseudocode directly reference the original scheme.
3. **Modular Design**: separation of primitives (`H`, `sqrt_mod`, `T`) and high-level API (`keygen`, `encrypt`, `decrypt`).
4. **General & Optimized**: Tonelli–Shanks for any prime, plus branch for \$p\equiv3\pmod4\$.
5. **Automated Testing**: `pytest` suite for end-to-end verification.
6. **CI/CD Ready**: PyPI publication via GitHub Actions.

---

## Installation

### From PyPI

```bash
pip install pqcrypto
```

### From Source

```bash
git clone https://github.com/4211421036/pqcrypto.git
cd pqcrypto
pip install .
```

---

## Usage Example

```python
import math

from pqcrypto import keygen, encrypt, decrypt

p = 10007
a = 5
P0 = (1, 0)

def max_block_size(p: int) -> int:
    bit_len = p.bit_length()
    return (bit_len - 1) // 8

def text_to_int_blocks(text: str, p: int) -> list[int]:
    raw_bytes = text.encode("utf-8")
    B = max_block_size(p)
    if B < 1:
        raise ValueError("Prime p terlalu kecil untuk menyimpan satu byte pun.")

    blocks = []
    # Hitung jumlah blok
    n_blocks = math.ceil(len(raw_bytes) / B)
    for i in range(n_blocks):
        start = i * B
        end = start + B
        chunk = raw_bytes[start:end]
        m_int = int.from_bytes(chunk, byteorder="big")
        if m_int >= p:
            raise ValueError("Blok integer melebihi modulus p.")
        blocks.append(m_int)

    return blocks


def int_blocks_to_text(blocks: list[int], p: int) -> str:
    all_bytes = bytearray()
    for m_int in blocks:
        if not (0 <= m_int < p):
            raise ValueError(f"Integer block {m_int} di luar range [0, p).")
        if m_int == 0:
            chunk_bytes = b"\x00"
        else:
            byte_len = math.ceil(m_int.bit_length() / 8)
            chunk_bytes = m_int.to_bytes(byte_len, byteorder="big")
        all_bytes.extend(chunk_bytes)

    return all_bytes.decode("utf-8", errors="strict")

def encrypt_text(
    text: str,
    k: int,
    public_Q: tuple[int, int],
    p: int,
    a: int,
    P0: tuple[int, int],
) -> list[dict]:
    int_blocks = text_to_int_blocks(text, p)
    ciphertext = []

    for m_int in int_blocks:
        # encrypt() sudah otomatis retry jika T^r gagal
        C1, C2, r = encrypt(m_int, public_Q, k, p, a, P0)
        ciphertext.append({
            "C1": (C1[0], C1[1]),
            "C2": (C2[0], C2[1]),
            "r": r,
        })

    return ciphertext

def decrypt_text(
    ciphertext: list[dict],
    k: int,
    p: int,
    a: int,
) -> str:
    int_blocks = []
    for block in ciphertext:
        x1, y1 = block["C1"]
        x2, y2 = block["C2"]
        r = block["r"]
        m_int = decrypt((x1, y1), (x2, y2), k, r, a, p)
        int_blocks.append(m_int)

    return int_blocks_to_text(int_blocks, p)

if __name__ == "__main__":
    # 6.1. Generate keypair
    private_k, public_Q = keygen(p, a, P0)
    print("=== Key Generation ===")
    print("Private k :", private_k)
    print("Public  Q :", public_Q)
    print()

    original_text = """
function hello(name) {
    console.log("Hello, " + name + "!");
}
hello("LAI User");
""".strip()

    print("=== Original Text ===")
    print(original_text)
    print()

    ciphertext = encrypt_text(original_text, private_k, public_Q, p, a, P0)
    print("=== Ciphertext (serialized) ===")
    for i, blk in enumerate(ciphertext):
        print(f"Block {i+1}: C1={blk['C1']}, C2={blk['C2']}, r={blk['r']}")

    print()
    recovered_text = decrypt_text(ciphertext, private_k, p, a)
    print("=== Decrypted Text ===")
    print(recovered_text)
    print()

    assert recovered_text == original_text, "Decryption mismatch!"
    print("Round-trip successful! Teks tepat sama dengan semula.")

```

---

## API Reference

| Function                             | Description                             |
| ------------------------------------ | --------------------------------------- |
| `H(x, y, s, p) -> int`               | Hash-based seed modulo \$p\$.           |
| `sqrt_mod(a, p) -> int`              | Modular square root via Tonelli–Shanks. |
| `T(point, s, a, p) -> (int, int)`    | One LAI transform step.                 |
| `keygen(p, a, P0) -> (k, Q)`         | Generate private key and public point.  |
| `encrypt(m, Q, p, a, P0) -> (C1,C2)` | Encrypt integer message.                |
| `decrypt(C1, C2, k, a, p) -> int`    | Decrypt ciphertext to integer.          |

---

## Testing

```bash
pytest --disable-warnings -q
```

---

## Contributing & Development

1. Fork the repo
2. Create branch: `git checkout -b feature/xyz`
3. Implement changes with corresponding tests
4. Run tests: `pytest`
5. Submit Pull Request

Please follow PEP 8 and include unit tests for new functionality.

---
