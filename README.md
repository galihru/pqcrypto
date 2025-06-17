# pqcrypto

<img src="https://4211421036.github.io/pqcrypto/logo.png" alt="pqcrypto Logo"/>

<p align="center" style="display: flex; justify-content: center; align-items: center; flex-wrap: wrap; gap: 0.5em;">
  <a href="https://pypi.org/project/laicrypto/">
    <img src="https://img.shields.io/pypi/v/laicrypto.svg" alt="PyPI version"/>
  </a>
  <a href="https://pypi.org/project/laicrypto/">
    <img src="https://img.shields.io/pypi/dm/laicrypto.svg" alt="PyPI downloads"/>
  </a>

  <a href="https://www.npmjs.com/package/pqlaicrypto">
    <img src="https://img.shields.io/npm/v/pqlaicrypto.svg" alt="npm version"/>
  </a>
  <a href="https://www.npmjs.com/package/pqlaicrypto">
    <img src="https://img.shields.io/npm/dm/pqlaicrypto.svg" alt="npm downloads"/>
  </a>

  <a href="https://rubygems.org/gems/laicrypto">
    <img src="https://img.shields.io/gem/v/laicrypto.svg" alt="RubyGems version"/>
  </a>
  <a href="https://rubygems.org/gems/laicrypto">
    <img src="https://img.shields.io/gem/dt/laicrypto.svg" alt="RubyGems downloads"/>
  </a>

  <a href="https://www.nuget.org/packages/PQCrypto.Lai/">
    <img src="https://img.shields.io/nuget/v/PQCrypto.Lai.svg" alt="NuGet version"/>
  </a>
  <a href="https://www.nuget.org/packages/PQCrypto.Lai/">
    <img src="https://img.shields.io/nuget/dt/PQCrypto.Lai.svg" alt="NuGet downloads"/>
  </a>

</p>

**Post-Quantum Lemniscate-AGM Isogeny (LAI) Encryption**

A multi-language reference implementation of the Lemniscate-AGM Isogeny (LAI) encryption scheme.  
LAI is a promising post-quantum cryptosystem based on isogenies of elliptic curves over lemniscate lattices, offering conjectured resistance against quantum-capable adversaries.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Mathematical Formulation](#mathematical-formulation)
3. [Features](#features)
4. [Releases & Package Managers](#releases--package-managers)  
   4.1. [Python (PyPI)](#python-pypi)  
   4.2. [JavaScript (npm)](#javascript-npm)  
   4.3. [Ruby (RubyGems)](#ruby-rubygems)  
   4.4. [.NET (NuGet)](#net-nuget)  
   4.5. [Java (Maven)](#java)  
5. [Usage Examples](#usage-examples)  
   5.1. [Python](#python)  
   5.2. [JavaScript](#javascripts)  
   5.3. [Ruby](#ruby)  
   5.4. [.NET (C#)](#net-c)  
   5.5. [Java](#java)  
6. [API Reference](#api-reference)  
7. [Testing](#testing)  
8. [Contributing & Development](#contributing--development)  
9. [License](#license)

---

## Project Overview

This library implements all core mathematical primitives and high-level APIs for LAI:

- **Hash-Based Seed Function**  
  $$\( H(x, y, s) = \mathrm{SHA256}\bigl(x\,\|\,y\,\|\,s\bigr) \bmod p \)$$
- **Modular Square Root** via Tonelli–Shanks (with fast branch if $$\(p \equiv 3 \pmod 4\)$$).
- **LAI Transformation**

  $$\[
T\bigl((x,y),\,s;\,a,\,p\bigr)
\;=\;
\Bigl(\,
  x' \;=\; \tfrac{x + a + h}{2} \bmod p,\;\;
  y' \;=\; \sqrt{x\,y + h}\bmod p
\Bigr)
\]
$$

  where $$\(h = H(x,y,s)\)$$.
- **Binary Exponentiation** of $$\(T\)$$ to compute $$\(T^k(P_0)\)$$ in $$\(O(\log k)\$$) time.
- **Key Generation, Encryption, and Decryption** routines for integer messages $$\(0 \le m < p\)$$.
- **Bulk JSON Decryption**: decrypt an entire JSON payload into raw bytes (e.g., to reconstruct a file or UTF-8 text).

All language‐specific wrappers expose identical API semantics under the hood. This makes pqcrypto ideal for cross-platform experiments, research, and educational purposes.

---

## Mathematical Formulation

### 1. Hash-Based Seed Function

For $$\(x, y, s \in \mathbb{Z}_p\)$$, define:

$$
\[
H(x, y, s) \;=\; \mathrm{SHA256}\bigl(\text{bytes}(x)\,\|\,\text{bytes}(y)\,\|\,\text{bytes}(s)\bigr)\;\bmod\;p,
\]
$$

where $$“\(\|\)”$$ denotes concatenation of the big-endian byte representations.

### 2. Modular Square Root (Tonelli–Shanks)

Solve $$\(z^2 \equiv a \pmod p\) for prime \(p\)$$:

- If $$\(p \equiv 3 \pmod 4\)$$:

$$
  \[
    z = a^{\frac{p+1}{4}} \bmod p.
  \]
$$

- Otherwise: apply the general Tonelli–Shanks algorithm in $$\(O(\log^2 p)\)$$ time.

### 3. LAI Transformation $$\(T\)$$

Given $$\((x,y)\in\mathbb{F}_p^2\)$$, parameter $$\(a\)$$, and seed index $$\(s\)$$, define

$$
\begin{cases}
  h = H(x,\,y,\,s),\[6pt]
  x' = \dfrac{x + a + h}{2}\bmod p,\[6pt]
  y' = \sqrt{x\,y + h}\;\bmod p.
\end{cases}
$$

Thus $$\(\;T\bigl((x,y),s;a,p\bigr) = (\,x',\,y'\,)\)$$.

### 4. Binary Exponentiation of $$\(T\)$$

To compute $$\(T^k(P_0)\)$$ efficiently:

```

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

### 5. Algorithmic API

**Key Generation**  
```

function keygen(p, a, P0):
   k ← random integer in [1, p−1]
   Q ← pow_T(P0, k)
   return (k, Q)

```

**Encryption**  
```

function encrypt(m, Q, p, a, P0):
   r  ← random integer in [1, p−1]
   C1 ← pow_T(P0, r)
   Sr ← pow_T(Q, r)
   M  ← (m mod p, 0)
   C2 ← ((M.x + Sr.x) mod p, (M.y + Sr.y) mod p)
   return (C1, C2)

```

**Decryption**  
```

function decrypt(C1, C2, k, a, p):
   S   ← pow_T(C1, k)
   M.x ← (C2.x − S.x) mod p
   return M.x

```

**Bulk Decryption (JSON)**  
```

function decryptAll(jsonPayload):
   parse p, a, P0, k, blocks[]
   for each block in blocks:
      (x1,y1) = block.C1
      (x2,y2) = block.C2
      r       = block.r
      M_int   = decrypt((x1,y1),(x2,y2),k,r,a,p)
      convert M_int into fixed-length big-endian B-byte chunk
      append to output byte buffer
   return outputBuffer

````

---

## Features

1. **Pure Implementations** (no native code)  
   - Python: only uses `hashlib`, `secrets` (stdlib).  
   - JavaScript: pure JS/BigInt.  
   - Ruby: pure Ruby + `openssl`.  
   - C#: uses `System.Numerics.BigInteger` (no external C/C++).  
   - Java: uses `java.math.BigInteger` + Jackson for JSON.

2. **Mathematically Annotated**  
   Every function corresponds exactly to the paper’s formulas.

3. **Modular Design**  
   Separation of low‐level primitives (`H`, `sqrt_mod`, `T`) from high‐level API (`keygen`, `encrypt`, `decrypt`).

4. **General & Optimized**  
   - Fast branch for $$\(p\equiv3\pmod4\)$$.  
   - Full Tonelli–Shanks fallback for any odd prime.

5. **Bulk JSON Decryption**  
   Produce or consume large ciphertext payloads (e.g., encrypted files, JavaScript code, JSON blobs).

6. **CI/CD Ready**  
   - Python: auto‐publish to PyPI via GitHub Actions.  
   - JS: auto‐publish to npm.  
   - Ruby: auto‐publish to RubyGems.  
   - C#: auto‐publish to NuGet & GitHub Packages.  
   - Java: auto‐publish to GitHub Packages (Maven).

---

## Releases & Package Managers

### Python (PyPI)

```bash
pip install laicrypto
````

### JavaScript (npm)

```bash
npm install pqlaicrypto
```

### Ruby (RubyGems)

```bash
gem install laicrypto
```

### .NET (NuGet)

```xml
<PackageReference Include="PQCrypto.Lai" Version="0.1.0" />
```

### Java (Maven Central / GitHub Packages)

```xml
<dependency>
  <groupId>com.pelajaran.pqcrypto</groupId>
  <artifactId>laicrypto</artifactId>
  <version>0.1.0</version>
</dependency>
```

---

## Usage Examples

Below are minimal “hello, world”-style code snippets for each language wrapper.

### Python

```python
import math
from pqcrypto import keygen, encrypt, decrypt

# 1. Setup parameters
p = 10007
a = 5
P0 = (1, 0)

# 2. Generate keypair
private_k, public_Q = keygen(p, a, P0)
print("Private k:", private_k)
print("Public  Q:", public_Q)

# 3. Encrypt integer m
message = 2024
C1, C2 = encrypt(message, public_Q, p, a, P0)
print("C1:", C1, " C2:", C2)

# 4. Decrypt using private_k
recovered = decrypt(C1, C2, private_k, a, p)
print("Recovered:", recovered)
assert recovered == message
```

If you need to encrypt an entire text/file, convert it to integer blocks via
`int.from_bytes(...)`, then call `encrypt(...)` on each block. See the
[Python demo](#python) in this README for details.

### JavaScripts

```js
// Install: npm install pqlaicrypto

const { keygen, encrypt, decrypt } = require("pqlaicrypto");

const p = 10007n;
const a = 5n;
const P0 = [1n, 0n];

// 1. Generate keypair
const { k, Q } = keygen(p, a, P0);
console.log("Private k:", k.toString());
console.log("Public  Q:", Q);

// 2. Encrypt a small integer
const m = 2024n;
const { C1, C2, r } = encrypt(m, Q, k, p, a, P0);
console.log("C1:", C1, "C2:", C2, "r:", r.toString());

// 3. Decrypt
const recovered = decrypt(C1, C2, k, r, a, p);
console.log("Recovered:", recovered.toString());
```

Use `BigInt`-aware file/block conversions to encrypt larger messages or files.

### Ruby

```ruby
# Install: gem install laicrypto
require "laicrypto"

p  = 10007
a  = 5
P0 = [1, 0]

# 1. Generate keypair
k, Q = LAI.keygen(p, a, P0)
puts "Private k: #{k}"
puts "Public  Q: #{Q.inspect}"

# 2. Encrypt integer
message = 2024
C1, C2, r = LAI.encrypt(message, Q, k, p, a, P0)
puts "C1: #{C1.inspect}  C2: #{C2.inspect}  r: #{r}"

# 3. Decrypt
recovered = LAI.decrypt(C1, C2, k, r, a, p)
puts "Recovered: #{recovered}"
```

Similar to Python, convert larger text to integer blocks using `String#bytes`
and `Integer()`.

### .NET (C#)

```csharp
// Install via NuGet: 
//   <PackageReference Include="PQCrypto.Lai" Version="0.1.0" />

using System;
using System.Numerics;
using PQCrypto; // namespace containing LaiCrypto

class Demo {
    static void Main(string[] args) {
        // 1. Setup parameters
        BigInteger p = 10007;
        BigInteger a = 5;
        LaiCrypto.Point P0 = new LaiCrypto.Point(1, 0);

        // 2. Generate keypair
        var kp = LaiCrypto.KeyGen(p, a, P0);
        Console.WriteLine($"Private k: {kp.k}");
        Console.WriteLine($"Public  Q: ({kp.Q.x}, {kp.Q.y})");

        // 3. Encrypt integer
        BigInteger message = 2024;
        var ct = LaiCrypto.Encrypt(message, kp.Q, p, a, P0);
        Console.WriteLine($"C1: ({ct.C1.x}, {ct.C1.y})  C2: ({ct.C2.x}, {ct.C2.y})  r: {ct.r}");

        // 4. Decrypt
        BigInteger recovered = LaiCrypto.Decrypt(ct.C1, ct.C2, kp.k, ct.r, a, p);
        Console.WriteLine($"Recovered: {recovered}");
        if (recovered != message) throw new Exception("Decryption mismatch!");
    }
}
```

To decrypt a JSON payload:

```csharp
using System.IO;
using Newtonsoft.Json.Linq; // or System.Text.Json

var json = File.ReadAllText("ciphertext.json");
var jNode = JObject.Parse(json);
byte[] plaintextBytes = LaiCrypto.DecryptAll(jNode);
string plaintext = System.Text.Encoding.UTF8.GetString(plaintextBytes);
```

### Java

```xml
<!-- In your pom.xml -->
<dependency>
  <groupId>com.pelajaran.pqcrypto</groupId>
  <artifactId>laicrypto</artifactId>
  <version>0.1.0</version>
</dependency>
```

```java
import com.pelajaran.pqcrypto.LaiCrypto;
import com.pelajaran.pqcrypto.LaiCrypto.Point;
import com.pelajaran.pqcrypto.LaiCrypto.KeyPair;
import com.pelajaran.pqcrypto.LaiCrypto.Ciphertext;

import java.math.BigInteger;

public class LAIDemo {
    public static void main(String[] args) throws Exception {
        // 1. Setup
        BigInteger p = BigInteger.valueOf(10007);
        BigInteger a = BigInteger.valueOf(5);
        Point P0 = new Point(BigInteger.ONE, BigInteger.ZERO);

        // 2. Generate key pair
        KeyPair kp = LaiCrypto.keyGen(p, a, P0);
        System.out.println("Private k: " + kp.k);
        System.out.println("Public  Q: (" + kp.Q.x + ", " + kp.Q.y + ")");

        // 3. Encrypt integer
        BigInteger message = BigInteger.valueOf(2024);
        Ciphertext ct = LaiCrypto.encrypt(message, kp.Q, p, a, P0);
        System.out.println("C1: (" + ct.C1.x + ", " + ct.C1.y + ")");
        System.out.println("C2: (" + ct.C2.x + ", " + ct.C2.y + ")");
        System.out.println("r:  " + ct.r);

        // 4. Decrypt
        BigInteger recovered = LaiCrypto.decrypt(ct.C1, ct.C2, kp.k, ct.r, a, p);
        System.out.println("Recovered: " + recovered);
    }
}
```

To decrypt a JSON payload in Java:

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

// ...
ObjectMapper mapper = new ObjectMapper();
JsonNode root = mapper.readTree(new File("ciphertext.json"));
byte[] plaintextBytes = LaiCrypto.decryptAll(root);
String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
```

---

## API Reference

| Function                                                                                                     | Description                                                                                    |
| ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| `H(x: BigInt, y: BigInt, s: BigInt, p: BigInt) → BigInt`                                                     | SHA-256(x \| y \| s) mod p.                                                                    |
| `sqrt_mod(a: BigInt, p: BigInt) → BigInt or null`                                                            | Compute $\sqrt{a} \bmod p$. Returns null if no root exists.                                    |
| `T(point: (BigInt,BigInt), s: BigInt, a: BigInt, p: BigInt) → (BigInt,BigInt)`                               | One LAI transform step.                                                                        |
| `pow_T(P, startS: BigInt, exp: BigInt, a: BigInt, p: BigInt) → (BigInt,BigInt)`                              | Compute $T^{\text{exp}}(P)$ by exponentiation by squaring.                                     |
| `keygen(p: BigInt, a: BigInt, P0: (BigInt,BigInt)) → (k: BigInt, Q: (BigInt,BigInt))`                        | Generate a random private key k and public point Q = Tᵏ(P₀).                                   |
| `encrypt(m: BigInt, Q: (BigInt,BigInt), k: BigInt, p: BigInt, a: BigInt, P0: (BigInt,BigInt)) → (C1, C2, r)` | Encrypt integer m (< p) yielding C1, C2, and randomness r.                                     |
| `decrypt(C1: (BigInt,BigInt), C2: (BigInt,BigInt), k: BigInt, r: BigInt, a: BigInt, p: BigInt) → BigInt`     | Decrypt one block, returning the original integer m.                                           |
| `decryptAll(jsonPayload) → byte[]`                                                                           | Read entire JSON ciphertext payload (array of blocks) and return concatenated plaintext bytes. |

---

## Testing

Each language wrapper includes its own test suite:

* **Python**:

  ```bash
  pytest --disable-warnings -q
  ```

* **JavaScript**:

  ```bash
  npm test
  ```

* **Ruby**:

  ```bash
  bundle exec rspec
  ```

* **.NET (C#)**:

  ```bash
  dotnet test
  ```

* **Java (Maven)**:

  ```bash
  mvn test
  ```

Make sure all tests pass locally before opening a pull request.

---

## Contributing & Development

1. **Fork the repository**
2. **Create a feature branch**

   ```bash
   git checkout -b feature/your_feature
   ```
3. **Implement changes**

   * Add or fix primitives/pseudo-code as needed.
   * Add unit tests for any new functionality.
4. **Run tests** in all supported languages.
5. **Commit & push**, then open a pull request.

Please follow PEP 8 style in Python, StandardJS in JavaScript, Ruby Style Guide, C# coding conventions, and Java conventions. Include thorough documentation for any new API.

---

## License

This project is licensed under the [MIT License](LICENSE).
