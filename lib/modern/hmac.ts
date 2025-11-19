/**
 * HMAC-SHA256 Implementation from Scratch
 * * Replaces CryptoJS.HmacSHA256
 */

export function hmacSign(message: string, key: string): string {
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(message);
  let keyBytes: Uint8Array = encoder.encode(key);

  const blockSize = 64; // 512 bits for SHA-256

  // 1. Prepare the key
  if (keyBytes.length > blockSize) {
    // Keys longer than block size are hashed
    keyBytes = sha256(keyBytes);
  }

  // If key is shorter than block size, pad with zeros (implicit in new Uint8Array)
  if (keyBytes.length < blockSize) {
    const newKey = new Uint8Array(blockSize);
    newKey.set(keyBytes);
    keyBytes = newKey;
  }

  // 2. Create Inner Pad (ipad) and Outer Pad (opad)
  const oPad = new Uint8Array(blockSize);
  const iPad = new Uint8Array(blockSize);

  for (let i = 0; i < blockSize; i++) {
    oPad[i] = keyBytes[i] ^ 0x5c;
    iPad[i] = keyBytes[i] ^ 0x36;
  }

  // 3. Perform Inner Hash: H(ipad || message)
  const innerInput = new Uint8Array(blockSize + msgBytes.length);
  innerInput.set(iPad);
  innerInput.set(msgBytes, blockSize);
  const innerHash = sha256(innerInput);

  // 4. Perform Outer Hash: H(opad || innerHash)
  const outerInput = new Uint8Array(blockSize + innerHash.length);
  outerInput.set(oPad);
  outerInput.set(innerHash, blockSize);
  const outerHash = sha256(outerInput);

  // 5. Return as Hex string
  return toHex(outerHash);
}

// --- Helper: Hex conversion ---

function toHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// --- Helper: SHA-256 Implementation (Pure TS) ---

function sha256(data: Uint8Array): Uint8Array {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);

  const k = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

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

  // Helper for right rotate
  const rrot = (x: number, n: number) => (x >>> n) | (x << (32 - n));

  for (let i = 0; i < padded.length; i += 64) {
    // Message Schedule
    for (let j = 0; j < 16; j++) {
      w[j] = (padded[i + j * 4] << 24) | (padded[i + j * 4 + 1] << 16) |
             (padded[i + j * 4 + 2] << 8) | (padded[i + j * 4 + 3]);
    }
    for (let j = 16; j < 64; j++) {
      const s0 = rrot(w[j - 15], 7) ^ rrot(w[j - 15], 18) ^ (w[j - 15] >>> 3);
      const s1 = rrot(w[j - 2], 17) ^ rrot(w[j - 2], 19) ^ (w[j - 2] >>> 10);
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];

    for (let j = 0; j < 64; j++) {
      const S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
      const ch = (e & f) ^ ((~e) & g);
      const temp1 = (hh + S1 + ch + k[j] + w[j]) >>> 0;
      const S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }

  const result = new Uint8Array(32);
  const resView = new DataView(result.buffer);
  for (let i = 0; i < 8; i++) resView.setUint32(i * 4, h[i], false);
  return result;
}