/*
 *   Copyright 2025 GALIH RIDHO UTOMO. All rights reserved.
 *
 *   pqcrypto.js - Post-Quantum Lemniscate-AGM Isogeny (LAI) Encryption
 * 
 *   JavaScript implementation of LAI cryptosystem:
 *     - Hash-based seed function H(x,y,s)
 *     - Modular square root (Tonelli-Shanks)
 *     - LAI transformation T
 *     - Key generation, encryption, and decryption
 *     - Bulk JSON decryption with caching
 *
 *   Part of pqcrypto multi-language project:
 *   https://github.com/4211421036/pqcrypto
 *
 *   Copyright (c) 2025 pqcrypto Project
 *   Licensed under MIT License
 * 
 *   Includes:
 *     - SHA-256 cryptographic hashing
 *     - BigInt arithmetic for mathematical operations
 *     - LocalStorage caching for performance
 *     - Automatic DOM injection of decrypted scripts
 */

function bytesToHex(e){return Array.from(e).map(e=>e.toString(16).padStart(2,"0")).join("")}async function H_js(e,t,n,r){const o=`${e}|${t}|${n}`,i=new TextEncoder,s=await crypto.subtle.digest("SHA-256",i.encode(o)),a=new Uint8Array(s),c=bytesToHex(a),u=BigInt("0x"+c);return u%BigInt(r)}function modPow(e,t,n){let r=1n;for(e%=n;t>0n;)t&1n&&(r=r*e%n),e=e*e%n,t>>=1n;return r}function legendreSymbol(e,t){return modPow(e,(t-1n)/2n,t)}function sqrt_mod_js(e,t){const n=((e%t)+t)%t;if(0n===n)return 0n;const r=legendreSymbol(n,t);if(r===t-1n)return null;if(t%4n===3n)return modPow(n,(t+1n)/4n,t);let o=t-1n,i=0n;for(;(o&1n)===0n;)o>>=1n,i+=1n;let s=2n;for(;legendreSymbol(s,t)!==t-1n;)s+=1n;let a=i,c=modPow(s,o,t),u=modPow(n,o,t),d=modPow(n,(o+1n)/2n,t);for(;;){if(1n===u)return d;let e=u,n=0n;for(let e=1n;e<a;e++)if(e=e*e%t,1n===e){n=e;break}const r=modPow(c,1n<<a-n-1n,t);a=n,c=r*r%t,u=u*c%t,d=d*r%t}}async function T_js(e,t,n,r){let[o,i]=[BigInt(e[0]),BigInt(e[1])],s=modPow(2n,BigInt(r)-2n,BigInt(r)),a=0,c=BigInt(t);for(;a<10;){const e=await H_js(o,i,c,r),t=(o+BigInt(n)+e)*s%BigInt(r),n=o*i+e%BigInt(r),u=sqrt_mod_js(n,BigInt(r));if(null!==u)return[t,u];c+=1n,a++}throw new Error(`T_js: Failed to compute square root of y^2 mod p after ${a} attempts.`)}async function _pow_T_range_js(e,t,n,r,o){let i=[BigInt(e[0]),BigInt(e[1])],s=BigInt(t);for(let e=0;e<n;e++)i=await T_js(i,s,r,o),s+=1n;return i}async function decrypt_block_js(e,t,n,r,o,i){const s=BigInt(i),a=BigInt(o),c=[BigInt(e[0]),BigInt(e[1])],u=[BigInt(t[0]),BigInt(t[1])],d=BigInt(n),l=BigInt(r),p=l+1n,m=await _pow_T_range_js(c,p,Number(d),a,s);return(u[0]-m[0]+s)%s}async function decrypt_all_text_js(e){const t=BigInt(e.p),n=BigInt(e.a),r=BigInt(e.k),o=e.blocks,i=Math.floor((t.toString(2).length-1)/8);function e(e){if(0n===e)return new Uint8Array([0]);const t=new Uint8Array(i);let n=e;for(let e=i-1;e>=0;e--)t[e]=Number(255n&n),n>>=8n;return t}let s=new Uint8Array(0);for(const n of o){const o=await decrypt_block_js(n.C1,n.C2,e.k,n.r,e.a,e.p),a=e(o);const r=new Uint8Array(s.length+a.length);r.set(s),r.set(a,s.length),s=r}return new TextDecoder("utf-8").decode(s)}async function getDecryptedOrCachedWithTiming(e,t){const n=localStorage.getItem(t);if(null!==n)return{text:n,durationMs:0};console.info(`[Cache] No cache, performing decryption. Key="${t}"`);const r=performance.now(),o=await decrypt_all_text_js(e),i=performance.now()-r;try{localStorage.setItem(t,o),localStorage.getItem(t)!==null}catch(e){console.error("[Cache] Failed to store in localStorage:",e)}return{text:o,durationMs:i}}async function fetchAndDecrypt(){let e;try{const t=await fetch("script.min.json",{cache:"no-store"});if(!t.ok)throw new Error(`HTTP ${t.status} fetching script.min.json`);e=await t.json()}catch(t){return void console.error("[fetchAndDecrypt] Unable to fetch script.min.json:",t)}const t="PQCrypto";let n;try{n=await getDecryptedOrCachedWithTiming(e,t)}catch(t){return void console.error("[fetchAndDecrypt] Decryption failed:",t)}try{const e=document.createElement("script");e.type="text/javascript",e.textContent=n.text,document.head.appendChild(e)}catch(e){console.error("[fetchAndDecrypt] Failed to inject decrypted script:",e)}}document.addEventListener("DOMContentLoaded",fetchAndDecrypt),window.decrypt_all_text_js=decrypt_all_text_js,window.getDecryptedOrCachedWithTiming=getDecryptedOrCachedWithTiming,window.fetchAndDecrypt=fetchAndDecrypt;
