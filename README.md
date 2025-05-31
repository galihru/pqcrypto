# pqcrypto

<img src="logo.png" />

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
git clone https://github.com/username/pqcrypto.git
cd pqcrypto
pip install .
```

---

## Usage Example

```python
from pqcrypto import keygen, encrypt, decrypt

# Parameters
a = 5
p = 10007
P0 = (1, 0)

# Key generation
private_k, public_Q = keygen(p, a, P0)

# Encryption
text = 1234
C1, C2 = encrypt(text, public_Q, p, a, P0)

# Decryption
m_out = decrypt(C1, C2, private_k, a, p)
assert m_out == text
print("Recovered message:", m_out)
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
