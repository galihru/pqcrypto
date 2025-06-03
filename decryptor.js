// decryptor_with_fetch_and_cache.js

/**
 * Helper: convert ArrayBuffer → Hexadecimal string
 */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * SHA-256-based seed function H(x, y, s) mod p:
 *     H(x, y, s) = SHA256("x|y|s") mod p
 * Returns: Promise<BigInt>
 */
async function H_js(x, y, s, p) {
  const inputString = `${x}|${y}|${s}`;
  const encoder = new TextEncoder();
  const data = encoder.encode(inputString);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = new Uint8Array(hashBuffer);
  const hashHex = bytesToHex(hashArray);
  const hashBig = BigInt("0x" + hashHex);
  return hashBig % BigInt(p);
}

/**
 * Modular exponentiation: base^exp mod modulus (all BigInt).
 * Returns: BigInt
 */
function modPow(base, exp, modulus) {
  let result = 1n;
  base = base % modulus;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % modulus;
    }
    base = (base * base) % modulus;
    exp >>= 1n;
  }
  return result;
}

/**
 * Compute the Legendre symbol (a | p) = a^((p-1)/2) mod p.
 * Returns: BigInt
 */
function legendreSymbol(a, p) {
  return modPow(a, (p - 1n) / 2n, p);
}

/**
 * Tonelli–Shanks algorithm for modular square root: sqrt_mod(a, p).
 * If a is not a quadratic residue modulo p, returns null.
 * Returns: BigInt (square root) or null.
 */
function sqrt_mod_js(a_in, p_in) {
  const a = ((a_in % p_in) + p_in) % p_in;
  if (a === 0n) return 0n;

  const ls = legendreSymbol(a, p_in);
  if (ls === p_in - 1n) {
    return null;
  }
  if (p_in % 4n === 3n) {
    return modPow(a, (p_in + 1n) / 4n, p_in);
  }

  let q = p_in - 1n;
  let s = 0n;
  while ((q & 1n) === 0n) {
    q >>= 1n;
    s += 1n;
  }
  let z = 2n;
  while (legendreSymbol(z, p_in) !== p_in - 1n) {
    z += 1n;
  }
  let m = s;
  let c = modPow(z, q, p_in);
  let t = modPow(a, q, p_in);
  let r = modPow(a, (q + 1n) / 2n, p_in);

  while (true) {
    if (t === 1n) return r;
    let t2i = t;
    let i = 0n;
    for (let j = 1n; j < m; j++) {
      t2i = (t2i * t2i) % p_in;
      if (t2i === 1n) {
        i = j;
        break;
      }
    }
    const b = modPow(c, 1n << (m - i - 1n), p_in);
    m = i;
    c = (b * b) % p_in;
    t = (t * c) % p_in;
    r = (r * b) % p_in;
  }
}

/**
 * Elliptic‐curve‐derived transformation T_js:
 *     T_js(point, s, a, p) → [x', y'] (both BigInt)
 * If sqrt_mod_js fails, increments s up to 10 iterations, then throws Error.
 */
async function T_js(point, s, a, p) {
  let [x, y] = [BigInt(point[0]), BigInt(point[1])];
  const inv2 = modPow(2n, BigInt(p) - 2n, BigInt(p));

  let attempts = 0;
  let currentSeed = BigInt(s);

  while (attempts < 10) {
    const hVal = await H_js(x, y, currentSeed, p);
    const xCandidate = ((x + BigInt(a) + hVal) * inv2) % BigInt(p);
    const ySquared = (x * y + hVal) % BigInt(p);
    const yCandidate = sqrt_mod_js(ySquared, BigInt(p));
    if (yCandidate !== null) {
      return [xCandidate, yCandidate];
    }
    currentSeed += 1n;
    attempts++;
  }

  throw new Error(
    `T_js: Failed to compute square root of y^2 mod p after ${attempts} attempts.`
  );
}

/**
 * Compute T^exp(P) by applying T_js iteratively with seed indices
 * from startS to (startS + exp - 1).
 * Returns: Promise<[BigInt, BigInt]> (final point coordinates)
 */
async function _pow_T_range_js(P, startS, exp, a, p) {
  let result = [BigInt(P[0]), BigInt(P[1])];
  let seedIndex = BigInt(startS);

  for (let i = 0; i < exp; i++) {
    result = await T_js(result, seedIndex, a, p);
    seedIndex += 1n;
  }
  return result;
}

/**
 * Decrypt a single block:
 *     decrypt_block_js(C1, C2, k, r, a, p) → BigInt M_int
 * where C1, C2 are elliptic‐curve points, k is the exponent count, r is the prior random index.
 */
async function decrypt_block_js(C1, C2, k, r, a, p) {
  const pBig = BigInt(p);
  const aBig = BigInt(a);
  const C1b = [BigInt(C1[0]), BigInt(C1[1])];
  const C2b = [BigInt(C2[0]), BigInt(C2[1])];
  const kBig = BigInt(k);
  const rBig = BigInt(r);

  // Generate ephemeral key S = T^k(C1) starting from seed index r + 1
  const startSeed = rBig + 1n;
  const S = await _pow_T_range_js(C1b, startSeed, Number(kBig), aBig, pBig);

  // Recover integer M: M_int = (C2.x − S.x) mod p
  const M_int = (C2b[0] - S[0] + pBig) % pBig;
  return M_int;
}

/**
 * decrypt_all_text_js(laiData) → Promise<String> (the recovered plaintext as UTF‐8)
 * Processes an array of ciphertext blocks, each containing { C1, C2, r }.
 */
async function decrypt_all_text_js(laiData) {
  const pBig = BigInt(laiData.p);
  const aBig = BigInt(laiData.a);
  const kBig = BigInt(laiData.k);
  const blocks = laiData.blocks;

  // Determine block‐byte size: B = floor((bit_length(p) - 1) / 8)
  const bitLength = pBig.toString(2).length;
  const B = Math.floor((bitLength - 1) / 8);

  // Convert BigInt M_int to a Uint8Array of length B (big‐endian)
  function intToBytes(m_int) {
    if (m_int === 0n) return new Uint8Array([0x00]);
    const arr = new Uint8Array(B);
    let temp = m_int;
    for (let i = B - 1; i >= 0; i--) {
      arr[i] = Number(temp & 0xffn);
      temp >>= 8n;
    }
    return arr;
  }

  // Concatenate all decrypted byte‐chunks
  let combined = new Uint8Array(0);
  for (const blk of blocks) {
    const M_int = await decrypt_block_js(
      blk.C1,
      blk.C2,
      laiData.k,
      blk.r,
      laiData.a,
      laiData.p
    );
    const chunkBytes = intToBytes(M_int);
    const merged = new Uint8Array(combined.length + chunkBytes.length);
    merged.set(combined);
    merged.set(chunkBytes, combined.length);
    combined = merged;
  }

  // Decode the combined byte array as UTF-8 string
  const decoder = new TextDecoder("utf-8");
  return decoder.decode(combined);
}

/**
 * getDecryptedOrCachedWithTiming(laiData, storageKey)
 *
 * Retrieve the decrypted plaintext from localStorage if available;
 * otherwise, measure decryption time, perform decryption,
 * store the result in localStorage, and return both plaintext and duration.
 *
 * Returns: Promise<{ text: String, durationMs: number }>
 */
async function getDecryptedOrCachedWithTiming(laiData, storageKey) {
  const cachedText = localStorage.getItem(storageKey);
  if (cachedText !== null) {
    console.info(`[Cache] Using cached plaintext (0 ms). Key="${storageKey}"`);
    return { text: cachedText, durationMs: 0 };
  }

  console.info(`[Cache] No cache, performing decryption. Key="${storageKey}"`);
  const t0 = performance.now();
  const decrypted = await decrypt_all_text_js(laiData);
  const t1 = performance.now();
  const elapsed = t1 - t0;

  try {
    localStorage.setItem(storageKey, decrypted);
    console.info(`[Cache] Stored plaintext under "${storageKey}". Verification:`,
      localStorage.getItem(storageKey) !== null);
  } catch (e) {
    console.error("[Cache] Failed to store in localStorage:", e);
  }

  console.info(`[Timing] Decryption took ${elapsed.toFixed(2)} ms.`);
  return { text: decrypted, durationMs: elapsed };
}

/**
 * fetchAndDecrypt()
 *
 * 1) Fetches "script.min.json" from the same directory.
 * 2) Attempts to retrieve from cache; if not present, decrypts.
 * 3) Dynamically injects a <script> tag containing the decrypted JavaScript code.
 */
async function fetchAndDecrypt() {
  let laiData;
  try {
    const response = await fetch("script.min.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} fetching script.min.json`);
    }
    laiData = await response.json();
  } catch (fetchError) {
    console.error("[fetchAndDecrypt] Unable to fetch script.min.json:", fetchError);
    return;
  }

  const cacheKey = "PQCrypto";
  let result;
  try {
    result = await getDecryptedOrCachedWithTiming(laiData, cacheKey);
  } catch (decryptError) {
    console.error("[fetchAndDecrypt] Decryption failed:", decryptError);
    return;
  }

  // Create a new <script> element and inject the decrypted JS code
  try {
    const scriptEl = document.createElement("script");
    scriptEl.type = "text/javascript";
    scriptEl.textContent = result.text;
    document.head.appendChild(scriptEl);
    console.info("[fetchAndDecrypt] Decrypted script injected successfully.");
  } catch (injectError) {
    console.error("[fetchAndDecrypt] Failed to inject decrypted script:", injectError);
  }
}

// Automatically invoke when the HTML includes this script (no inline HTML code required).
document.addEventListener("DOMContentLoaded", fetchAndDecrypt);

// Expose public functions if needed elsewhere
window.decrypt_all_text_js = decrypt_all_text_js;
window.getDecryptedOrCachedWithTiming = getDecryptedOrCachedWithTiming;
window.fetchAndDecrypt = fetchAndDecrypt;
