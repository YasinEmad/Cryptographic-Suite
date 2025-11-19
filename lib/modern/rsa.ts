/**
 * RSA-OAEP Implementation from Scratch
 *
 * INCLUDES:
 * 1. BigInt Math (Modular Exponentiation, Modular Inverse, Primality Testing)
 * 2. SHA-256 Hashing (Pure TS implementation)
 * 3. OAEP Padding Scheme (MGF1)
 * 4. ASN.1/DER Encoding (To generate valid PEM strings)
 * 5. Base64 Utilities
 *
 * NOTE: Generating 2048-bit keys in pure JavaScript is computationally expensive
 * and may take several seconds (or longer) depending on the device.
 *
 * SECURITY WARNING: This is for educational/algorithmic demonstration.
 * In production, always use Web Crypto API or audited native libraries
 * as they are constant-time and side-channel resistant.
 */

// --- Main Exported Functions ---

export async function generateRsaKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
  // 1. Constants
  const e = 65537n;
  const bitLength = 2048;
  const pBitLength = bitLength / 2;

  // 2. Generate Primes p and q
  // Note: This is the slow part in pure JS
  let p = await generatePrime(pBitLength);
  let q = await generatePrime(pBitLength);

  // Ensure p != q
  while (p === q) {
    q = await generatePrime(pBitLength);
  }

  // 3. Compute n (modulus) and phi
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);

  // 4. Compute d (private exponent)
  // d = e^(-1) mod phi
  const d = modInverse(e, phi);

  // 5. Compute CRT coefficients (standard for Private Key PEMs to speed up calculation,
  //    though we will use raw d for decryption here for simplicity of code)
  const dP = d % (p - 1n);
  const dQ = d % (q - 1n);
  const qInv = modInverse(q, p);

  // 6. Encode to ASN.1 DER -> PEM
  const pubKeyDER = encodePublicKeyDER(n, e);
  const privKeyDER = encodePrivateKeyDER(n, e, d, p, q, dP, dQ, qInv);

  return {
    publicKey: toPem(pubKeyDER, "PUBLIC KEY"),
    privateKey: toPem(privKeyDER, "RSA PRIVATE KEY"),
  };
}

export async function rsaEncrypt(plaintext: string, publicKeyPem: string): Promise<string> {
  // 1. Parse Public Key
  const { n, e } = parsePublicKeyPEM(publicKeyPem);

  // 2. OAEP Padding
  const msgBytes = new TextEncoder().encode(plaintext);
  const k = (n.toString(16).length + 1) >> 1; // Approximate byte length of modulus
  const padded = oaepPad(msgBytes, k);

  // 3. Convert padded bytes to BigInt
  const mInt = os2ip(padded);

  // 4. Raw RSA Encryption: c = m^e mod n
  const cInt = modPow(mInt, e, n);

  // 5. Convert to bytes -> Base64
  const cBytes = i2osp(cInt, k);
  return arrayBufferToBase64(cBytes.buffer as ArrayBuffer);
}

export async function rsaDecrypt(ciphertext: string, privateKeyPem: string): Promise<string> {
  // 1. Parse Private Key
  const { n, d } = parsePrivateKeyPEM(privateKeyPem);

  // 2. Decode Base64 -> BigInt
  const cBytes = base64ToArrayBuffer(ciphertext);
  const cInt = os2ip(new Uint8Array(cBytes));

  // 3. Raw RSA Decryption: m = c^d mod n
  // (Note: A full optimization uses CRT with p, q, but simple exponentiation works)
  const mInt = modPow(cInt, d, n);

  // 4. Convert BigInt -> Bytes
  const k = (n.toString(16).length + 1) >> 1;
  const padded = i2osp(mInt, k);

  // 5. OAEP Unpadding
  const msgBytes = oaepUnpad(padded, k);

  return new TextDecoder().decode(msgBytes);
}


// --- Section 1: Math & BigInt Utils ---

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) res = (res * base) % mod;
    base = (base * base) % mod;
    exp /= 2n;
  }
  return res;
}

function modInverse(a: bigint, m: bigint): bigint {
  let m0 = m;
  let y = 0n;
  let x = 1n;
  if (m === 1n) return 0n;
  while (a > 1n) {
    const q = a / m;
    let t = m;
    m = a % m;
    a = t;
    t = y;
    y = x - q * y;
    x = t;
  }
  if (x < 0n) x += m0;
  return x;
}

// Miller-Rabin Primality Test
function isPrime(n: bigint, k: number = 5): boolean {
  if (n <= 1n || n === 4n) return false;
  if (n <= 3n) return true;

  // Find r and d such that n - 1 = 2^r * d
  let d = n - 1n;
  let r = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    r++;
  }

  // Witness loop
  for (let i = 0; i < k; i++) {
    const a = 2n + BigInt(Math.floor(Math.random() * (Number(n - 4n))));
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let continueWitness = false;
    for (let j = 0n; j < r - 1n; j++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        continueWitness = true;
        break;
      }
    }
    if (continueWitness) continue;
    return false;
  }
  return true;
}

// Random BigInt generator
function getRandomBigInt(bits: number): bigint {
  // Generate random bytes
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  // Ensure strictly the right number of bits for the top byte
  // and set the bottom bit to 1 to ensure it's odd
  if (bytes.length > 0) {
      const mask = (1 << (bits % 8)) - 1;
      if (bits % 8 !== 0) bytes[0] &= mask;
      bytes[bytes.length - 1] |= 1; 
  }
  
  // Convert bytes to BigInt
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) + BigInt(b);
  }
  return result;
}

async function generatePrime(bits: number): Promise<bigint> {
  while (true) {
    const candidate = getRandomBigInt(bits);
    // Check small primes first for speed
    if (candidate % 3n === 0n || candidate % 5n === 0n || candidate % 7n === 0n) continue;
    if (isPrime(candidate)) return candidate;
    // Yield to main thread occasionally to prevent freezing
    if (Math.random() < 0.05) await new Promise((r) => setTimeout(r, 0));
  }
}

// OS2IP: Octet String to Integer Primitive
function os2ip(bytes: Uint8Array): bigint {
  let res = 0n;
  for (const b of bytes) {
    res = (res << 8n) + BigInt(b);
  }
  return res;
}

// I2OSP: Integer to Octet String Primitive
function i2osp(x: bigint, len: number): Uint8Array {
  const res = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    res[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return res;
}


// --- Section 2: SHA-256 Implementation (Pure TS) ---

class Sha256 {
  private h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);
  
  private k = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  private rrot(x: number, n: number) { return (x >>> n) | (x << (32 - n)); }
  
  process(data: Uint8Array): Uint8Array {
    // Padding
    const bitLen = data.length * 8;
    const padLen = ((56 - (data.length + 1) % 64) + 64) % 64;
    const padded = new Uint8Array(data.length + 1 + padLen + 8);
    padded.set(data);
    padded[data.length] = 0x80;
    
    // Append length (big endian 64-bit integer)
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296), false); // High 32
    view.setUint32(padded.length - 4, bitLen >>> 0, false); // Low 32

    const w = new Uint32Array(64);
    
    for (let i = 0; i < padded.length; i += 64) {
      for (let j = 0; j < 16; j++) {
        w[j] = (padded[i + j * 4] << 24) | (padded[i + j * 4 + 1] << 16) | 
               (padded[i + j * 4 + 2] << 8) | (padded[i + j * 4 + 3]);
      }
      for (let j = 16; j < 64; j++) {
        const s0 = this.rrot(w[j - 15], 7) ^ this.rrot(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        const s1 = this.rrot(w[j - 2], 17) ^ this.rrot(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
      }

      let [a, b, c, d, e, f, g, h] = this.h;

      for (let j = 0; j < 64; j++) {
        const S1 = this.rrot(e, 6) ^ this.rrot(e, 11) ^ this.rrot(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + S1 + ch + this.k[j] + w[j]) >>> 0;
        const S0 = this.rrot(a, 2) ^ this.rrot(a, 13) ^ this.rrot(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g; g = f; f = e; d = (d + temp1) >>> 0;
        e = (temp1 + temp2) >>> 0; e = d + temp1 >>> 0; e = temp1 + d; e = d; // Wait logic fix below
        // Correct assignment shift
        h=g; g=f; f=e; e=(d+temp1)>>>0; d=c; c=b; b=a; a=(temp1+temp2)>>>0;
      }

      this.h[0] = (this.h[0] + a) >>> 0;
      this.h[1] = (this.h[1] + b) >>> 0;
      this.h[2] = (this.h[2] + c) >>> 0;
      this.h[3] = (this.h[3] + d) >>> 0;
      this.h[4] = (this.h[4] + e) >>> 0;
      this.h[5] = (this.h[5] + f) >>> 0;
      this.h[6] = (this.h[6] + g) >>> 0;
      this.h[7] = (this.h[7] + h) >>> 0;
    }

    const result = new Uint8Array(32);
    const resView = new DataView(result.buffer);
    for(let i=0; i<8; i++) resView.setUint32(i*4, this.h[i], false);
    return result;
  }
}

function sha256(data: Uint8Array): Uint8Array {
  return new Sha256().process(data);
}


// --- Section 3: OAEP Padding ---

function mgf1(seed: Uint8Array, len: number): Uint8Array {
  const t = new Uint8Array(len);
  let counter = 0;
  let offset = 0;
  while (offset < len) {
    const c = new Uint8Array(4);
    new DataView(c.buffer).setUint32(0, counter, false);
    const hashInput = new Uint8Array(seed.length + 4);
    hashInput.set(seed);
    hashInput.set(c, seed.length);
    const hash = sha256(hashInput);
    const copyLen = Math.min(32, len - offset);
    t.set(hash.subarray(0, copyLen), offset);
    offset += copyLen;
    counter++;
  }
  return t;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const res = new Uint8Array(a.length);
  for(let i=0; i<a.length; i++) res[i] = a[i] ^ b[i];
  return res;
}

function oaepPad(message: Uint8Array, k: number): Uint8Array {
  const hLen = 32; // SHA-256 length
  const maxLen = k - 2 * hLen - 2;
  if (message.length > maxLen) throw new Error("Message too long");

  const label = new Uint8Array(0); // Empty label
  const lHash = sha256(label);
  const ps = new Uint8Array(k - message.length - 2 * hLen - 2); // Zero padding
  
  const db = new Uint8Array(hLen + ps.length + 1 + message.length);
  db.set(lHash);
  db.set(ps, hLen);
  db[hLen + ps.length] = 0x01;
  db.set(message, hLen + ps.length + 1);

  const seed = new Uint8Array(hLen);
  for(let i=0; i<hLen; i++) seed[i] = Math.floor(Math.random() * 256);

  const dbMask = mgf1(seed, k - hLen - 1);
  const maskedDB = xor(db, dbMask);

  const seedMask = mgf1(maskedDB, hLen);
  const maskedSeed = xor(seed, seedMask);

  const em = new Uint8Array(k);
  em[0] = 0x00;
  em.set(maskedSeed, 1);
  em.set(maskedDB, 1 + hLen);
  return em;
}

function oaepUnpad(em: Uint8Array, k: number): Uint8Array {
  const hLen = 32;
  if (em[0] !== 0x00) throw new Error("Decryption error: First byte not 0");

  const maskedSeed = em.subarray(1, 1 + hLen);
  const maskedDB = em.subarray(1 + hLen);

  const seedMask = mgf1(maskedDB, hLen);
  const seed = xor(maskedSeed, seedMask);

  const dbMask = mgf1(seed, k - hLen - 1);
  const db = xor(maskedDB, dbMask);

  const lHash = sha256(new Uint8Array(0));
  // Check label hash
  for(let i=0; i<hLen; i++) {
    if(db[i] !== lHash[i]) throw new Error("Decryption error: Hash mismatch");
  }

  let index = hLen;
  while(index < db.length && db[index] === 0x00) index++;
  
  if (index >= db.length || db[index] !== 0x01) throw new Error("Decryption error: Padding invalid");

  return db.subarray(index + 1);
}


// --- Section 4: ASN.1/DER Encoding ---

function encodeLenBytes(len: number): number[] {
  if (len < 128) return [len];
  const bytes: number[] = [];
  while (len > 0) {
    bytes.unshift(len & 0xff);
    len = len >>> 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

function encodeInteger(n: bigint): Uint8Array {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for(let i=0; i<bytes.length; i++) bytes[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  
  // ASN.1 Integer must be signed. If high bit is set, prepend 0x00
  if (bytes[0] & 0x80) {
    const b = new Uint8Array(bytes.length + 1);
    b[0] = 0x00;
    b.set(bytes, 1);
    return b;
  }
  return bytes;
}

function encodeSequence(items: Uint8Array[]): Uint8Array {
  const totalLen = items.reduce((sum, arr) => sum + arr.length + encodeLenBytes(arr.length).length + 1, 0);
  // Actually, items are usually "Tag | Len | Value" already? 
  // No, helper below:
  let payloadLen = 0;
  items.forEach(i => payloadLen += i.length);
  
  const headerLenBytes = encodeLenBytes(payloadLen);
  const totalSize = 1 + headerLenBytes.length + payloadLen;
  
  const seq = new Uint8Array(totalSize);
  seq[0] = 0x30; // SEQUENCE
  let offset = 1;
  headerLenBytes.forEach(b => seq[offset++] = b);
  
  items.forEach(item => {
    seq.set(item, offset);
    offset += item.length;
  });
  return seq;
}

function createDerInt(n: bigint): Uint8Array {
  const val = encodeInteger(n);
  const lenBytes = encodeLenBytes(val.length);
  const res = new Uint8Array(1 + lenBytes.length + val.length);
  res[0] = 0x02; // INTEGER
  let offset = 1;
  lenBytes.forEach(b => res[offset++] = b);
  res.set(val, offset);
  return res;
}

function encodePublicKeyDER(n: bigint, e: bigint): Uint8Array {
  // PKCS#1 Public Key: SEQUENCE { n, e }
  return encodeSequence([createDerInt(n), createDerInt(e)]);
}

function encodePrivateKeyDER(n: bigint, e: bigint, d: bigint, p: bigint, q: bigint, dP: bigint, dQ: bigint, qInv: bigint): Uint8Array {
  // PKCS#1 Private Key
  return encodeSequence([
    createDerInt(0n), // version
    createDerInt(n),
    createDerInt(e),
    createDerInt(d),
    createDerInt(p),
    createDerInt(q),
    createDerInt(dP),
    createDerInt(dQ),
    createDerInt(qInv)
  ]);
}

// --- DER Parsers (Minimal) ---

function parseDerInt(data: Uint8Array, offset: { val: number }): bigint {
  if (data[offset.val++] !== 0x02) throw new Error("Not an int");
  let len = data[offset.val++];
  if (len & 0x80) {
    const byteCount = len & 0x7f;
    len = 0;
    for(let i=0; i<byteCount; i++) len = (len << 8) | data[offset.val++];
  }
  let hex = "";
  for(let i=0; i<len; i++) {
    const b = data[offset.val++];
    hex += b.toString(16).padStart(2, '0');
  }
  return BigInt("0x" + hex);
}

function parsePublicKeyPEM(pem: string): { n: bigint, e: bigint } {
  const buffer = new Uint8Array(pemToArrayBuffer(pem));
  // Basic parser. If it's SPKI (begins with PUBLIC KEY), we need to skip the algo identifier.
  // If PKCS#1 (RSA PUBLIC KEY), it's direct.
  // Simplified: Assume standard header skipping logic or naive check
  let offset = { val: 0 };
  
  // Skip sequence tag/len
  if (buffer[offset.val++] !== 0x30) throw new Error("Invalid DER");
  let len = buffer[offset.val++];
  if (len & 0x80) {
      const n = len & 0x7f;
      offset.val += n;
  }

  // Heuristic: Check if next is AlgorithmIdentifier (Sequence) -> SPKI
  if (buffer[offset.val] === 0x30) {
     // Skip AlgorithmIdentifier
     // We just manually jump ahead to the BitString containing the actual key
     // This is "hacky" but effective for a single-file scratch implementation
     // A real ASN.1 parser is too large.
     // SPKI: Seq [ Seq [ OID... ], BitString [ ... key ... ] ]
     // We just search for the second BitString (0x03)
     while (offset.val < buffer.length && buffer[offset.val] !== 0x03) offset.val++;
     if (offset.val >= buffer.length) throw new Error("Unknown Key Format");
     
     offset.val++; // Tag 0x03
     // Skip len
     let blen = buffer[offset.val++];
     if (blen & 0x80) { offset.val += (blen & 0x7f); }
     offset.val++; // Skip unused bits byte
     
     // Now we are at the Inner RSAPublicKey Sequence
     if (buffer[offset.val++] !== 0x30) throw new Error("Inner not sequence");
     let ilen = buffer[offset.val++];
     if (ilen & 0x80) { offset.val += (ilen & 0x7f); }
  }

  const n = parseDerInt(buffer, offset);
  const e = parseDerInt(buffer, offset);
  return { n, e };
}

function parsePrivateKeyPEM(pem: string): { n: bigint, d: bigint } {
  const buffer = new Uint8Array(pemToArrayBuffer(pem));
  let offset = { val: 0 };
  
  if (buffer[offset.val++] !== 0x30) throw new Error("Invalid DER");
  // Skip len
  let len = buffer[offset.val++];
  if (len & 0x80) { offset.val += (len & 0x7f); }
  
  // PKCS#8 (PRIVATE KEY) vs PKCS#1 (RSA PRIVATE KEY)
  // PKCS#8 starts with Version (Int), then AlgorithmIdentifier
  // PKCS#1 starts with Version (Int 0), then n
  
  const version = parseDerInt(buffer, offset);
  
  if (pem.includes("BEGIN PRIVATE KEY")) {
    // PKCS#8: Skip AlgorithmIdentifier to get OctetString
    // Search for Octet String 0x04
    while (offset.val < buffer.length && buffer[offset.val] !== 0x04) offset.val++;
     if (offset.val >= buffer.length) throw new Error("Unknown Key Format");
    offset.val++; // Tag 0x04
    let olen = buffer[offset.val++];
    if (olen & 0x80) { offset.val += (olen & 0x7f); }
    
    // Now inside the PrivateKey Sequence
    if (buffer[offset.val++] !== 0x30) throw new Error("Inner not sequence");
    // Skip len
    let ilen = buffer[offset.val++];
    if (ilen & 0x80) { offset.val += (ilen & 0x7f); }
    
    // Parse inner version
    parseDerInt(buffer, offset);
  }

  const n = parseDerInt(buffer, offset);
  const e = parseDerInt(buffer, offset);
  const d = parseDerInt(buffer, offset);
  return { n, d };
}


// --- Section 5: Base64 & PEM Formatting ---

function arrayBufferToBase64(buffer: ArrayBufferLike): string {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // In Node, use Buffer. In Browser/Generic, use standard logic if btoa unavailable, 
  // but usually btoa is available in JS environments. 
  // Manual fallback for "Pure Scratch":
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let output = "";
  for (let i = 0; i < len; i += 3) {
      const b1 = bytes[i];
      const b2 = i + 1 < len ? bytes[i+1] : 0;
      const b3 = i + 2 < len ? bytes[i+2] : 0;
      
      const e1 = b1 >> 2;
      const e2 = ((b1 & 3) << 4) | (b2 >> 4);
      const e3 = ((b2 & 15) << 2) | (b3 >> 6);
      const e4 = b3 & 63;
      
      output += chars.charAt(e1) + chars.charAt(e2);
      output += (i + 1 < len) ? chars.charAt(e3) : "=";
      output += (i + 2 < len) ? chars.charAt(e4) : "=";
  }
  return output;
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const lookup = new Uint8Array(256);
  for (let i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;
  
  base64 = base64.replace(/[=]+$/, ''); // Remove padding
  let bufferLength = base64.length * 0.75;
  const len = base64.length;
  const bytes = new Uint8Array(bufferLength);
  let p = 0;
  for (let i = 0; i < len; i += 4) {
      const encoded1 = lookup[base64.charCodeAt(i)];
      const encoded2 = lookup[base64.charCodeAt(i+1)];
      const encoded3 = lookup[base64.charCodeAt(i+2)];
      const encoded4 = lookup[base64.charCodeAt(i+3)];

      bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
      if (i + 2 < len) bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
      if (i + 3 < len) bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
  }
  return bytes.buffer as ArrayBuffer;
}

function toPem(buffer: Uint8Array, label: string): string {
  const base64 = arrayBufferToBase64(buffer.buffer as ArrayBuffer);
  const formattedBase64 = base64.match(/.{1,64}/g)?.join("\n") || "";
  return `-----BEGIN ${label}-----\n${formattedBase64}\n-----END ${label}-----`;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN.*?-----/g, "")
    .replace(/-----END.*?-----/g, "")
    .replace(/\s/g, "");
  return base64ToArrayBuffer(base64);
}