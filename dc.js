// ───────────────────────────────────────────────────────────────────────
// decryptor.js
//
//   This file defines window.decrypt_all_text_js(...) (your existing helper)
//   and then immediately fetches + decrypts `enkripsi.json` and injects
//   the recovered JavaScript into the page.  
// ───────────────────────────────────────────────────────────────────────

// === (A) YOUR existing helper functions, verbatim ===
//    Copy exactly from your “decrypt_all_text_js” snippet (no changes),
//    except remove the “window.decrypt_all_text_js = …” export line.
//    We will re‐export it at the very end.

// (1) bytesToHex, H_js, modPow, legendreSymbol, sqrt_mod_js, T_js, _pow_T_range_js, decrypt_block_js:

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function H_js(x, y, s, p) {
  const str = `${x}|${y}|${s}`;
  const enc = new TextEncoder();
  const data = enc.encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = new Uint8Array(hashBuffer);
  const hashHex = bytesToHex(hashArray);
  const hashBig = BigInt("0x" + hashHex);
  return hashBig % BigInt(p);
}

function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

function legendreSymbol(a, p) {
  return modPow(a, (p - 1n) / 2n, p);
}

function sqrt_mod_js(a_in, p_in) {
  const a = ((a_in % p_in) + p_in) % p_in;
  if (a === 0n) return 0n;

  const ls = legendreSymbol(a, p_in);
  if (ls === p_in - 1n) {
    return null;
  }
  if ((p_in % 4n) === 3n) {
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

async function T_js(point, s, a, p) {
  let [x, y] = [BigInt(point[0]), BigInt(point[1])];
  const inv2 = modPow(2n, BigInt(p) - 2n, BigInt(p));

  let trials = 0;
  let s_cur = BigInt(s);

  while (trials < 10) {
    const h_val = await H_js(x, y, s_cur, p);
    const x_cand = ((x + BigInt(a) + h_val) * inv2) % BigInt(p);
    const y_sq = (x * y + h_val) % BigInt(p);
    const y_cand = sqrt_mod_js(y_sq, BigInt(p));
    if (y_cand !== null) {
      return [x_cand, y_cand];
    }
    s_cur += 1n;
    trials++;
  }
  throw new Error(
    `T_js: failed to find sqrt for y^2 mod p after ${trials} trials.`
  );
}

async function _pow_T_range_js(P, startS, exp, a, p) {
  let result = [BigInt(P[0]), BigInt(P[1])];
  let s_idx = BigInt(startS);

  for (let i = 0; i < exp; i++) {
    result = await T_js(result, s_idx, a, p);
    s_idx += 1n;
  }
  return result;
}

async function decrypt_block_js(C1, C2, k, r, a, p) {
  const p_big = BigInt(p);
  const a_big = BigInt(a);
  const C1_b = [BigInt(C1[0]), BigInt(C1[1])];
  const C2_b = [BigInt(C2[0]), BigInt(C2[1])];
  const k_big = BigInt(k);
  const r_big = BigInt(r);

  const startSeed = r_big + 1n; // seeds (r+1) .. (r+k)
  const S = await _pow_T_range_js(C1_b, startSeed, Number(k_big), a_big, p_big);
  const M_int = (C2_b[0] - S[0] + p_big) % p_big;
  return M_int;
}

async function decrypt_all_text_js(laiData) {
  const p_big = BigInt(laiData.p);
  const a_big = BigInt(laiData.a);
  const k_big = BigInt(laiData.k);
  const blocks = laiData.blocks;

  const bit_len = p_big.toString(2).length;
  const B = Math.floor((bit_len - 1) / 8);

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

  let combined = new Uint8Array(0);
  for (const blk of blocks) {
    const M_int = await decrypt_block_js(blk.C1, blk.C2, laiData.k, blk.r, laiData.a, laiData.p);
    const chunkBytes = intToBytes(M_int);
    const tmp = new Uint8Array(combined.length + chunkBytes.length);
    tmp.set(combined);
    tmp.set(chunkBytes, combined.length);
    combined = tmp;
  }

  const decoder = new TextDecoder("utf-8");
  return decoder.decode(combined);
}

// Re‐export so that index.html (or anyone) can call it:
window.decrypt_all_text_js = decrypt_all_text_js;


// === (B) Immediately “bootstrap” fetch+decryption+injection ===

(async () => {
  // 1) Fetch the encrypted JSON
  let response;
  try {
    response = await fetch("script.min.json");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
  } catch (err) {
    console.error("❌ Failed to fetch enkripsi.json:", err);
    return;
  }

  let payload;
  try {
    payload = await response.json();
  } catch (err) {
    console.error("❌ Could not parse JSON:", err);
    return;
  }

  // 2) Call decrypt_all_text_js(payload) to get the recovered JS text
  let recoveredText;
  try {
    recoveredText = await decrypt_all_text_js(payload);
  } catch (err) {
    console.error("❌ decrypt_all_text_js() threw an error:", err);
    return;
  }

  // 3) Inject as a <script> tag so it runs immediately
  const scriptTag = document.createElement("script");
  scriptTag.type = "text/javascript";
  scriptTag.text = recoveredText;
  document.body.appendChild(scriptTag);

  // 4) Remove “Loading…” overlay (if present)
  const overlay = document.getElementById("loading-overlay");
  if (overlay) overlay.remove();

  console.log("✅ Decryption complete, original JS has been injected.");
})();
