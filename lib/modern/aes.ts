/**
 * AES Implementation from Scratch
 * Supports: 128/192/256-bit Keys
 * Modes: CBC, CTR, OFB
 * Padding: PKCS#7 (for CBC only)
 * * EXPLANATION OF CTR vs OFB SIMILARITY:
 * If you encrypt less than or equal to 16 bytes (one block), CTR and OFB 
 * will produce the EXACT SAME ciphertext. This is mathematically expected.
 * - CTR Block 1: Keystream = Encrypt(IV)
 * - OFB Block 1: Keystream = Encrypt(IV)
 * They only diverge on the second block (bytes 17+).
 */

// --- Main Exports ---

export async function aesEncrypt(plaintext: string, key: string, iv: string, modeName: string): Promise<string> {
    try {
        const keyBytes = stringToUtf8Bytes(key);
        const ivBytes = stringToUtf8Bytes(iv);
        const plainBytes = stringToUtf8Bytes(plaintext);

        validateKeyAndIV(keyBytes, ivBytes);

        let encryptedBytes: Uint8Array;

        switch (modeName.toUpperCase()) {
            case 'CBC':
                encryptedBytes = modeCBCEncrypt(plainBytes, keyBytes, ivBytes);
                break;
            case 'CTR':
                encryptedBytes = modeCTREncrypt(plainBytes, keyBytes, ivBytes);
                break;
            case 'OFB':
                encryptedBytes = modeOFBEncrypt(plainBytes, keyBytes, ivBytes);
                break;
            default:
                throw new Error(`Unsupported AES mode: ${modeName}`);
        }

        return bytesToBase64(encryptedBytes);
    } catch (e: any) {
        throw new Error("AES Encrypt Error: " + e.message);
    }
}

export async function aesDecrypt(ciphertext: string, key: string, iv: string, modeName: string): Promise<string> {
    try {
        const keyBytes = stringToUtf8Bytes(key);
        const ivBytes = stringToUtf8Bytes(iv);
        const cipherBytes = base64ToBytes(ciphertext);

        validateKeyAndIV(keyBytes, ivBytes);

        let decryptedBytes: Uint8Array;

        switch (modeName.toUpperCase()) {
            case 'CBC':
                decryptedBytes = modeCBCDecrypt(cipherBytes, keyBytes, ivBytes);
                break;
            case 'CTR':
                // CTR decryption is symmetric to encryption (stream cipher)
                decryptedBytes = modeCTREncrypt(cipherBytes, keyBytes, ivBytes);
                break;
            case 'OFB':
                // OFB decryption is symmetric to encryption (stream cipher)
                decryptedBytes = modeOFBEncrypt(cipherBytes, keyBytes, ivBytes);
                break;
            default:
                throw new Error(`Unsupported AES mode: ${modeName}`);
        }

        return utf8BytesToString(decryptedBytes);
    } catch (e: any) {
        throw new Error("AES Decrypt Error: " + e.message);
    }
}

// --- Validation ---

function validateKeyAndIV(key: Uint8Array, iv: Uint8Array) {
    if (![16, 24, 32].includes(key.length)) {
        throw new Error(`Invalid key length: ${key.length} bytes. Must be 16, 24, or 32.`);
    }
    if (iv.length !== 16) {
        throw new Error(`Invalid IV length: ${iv.length} bytes. Must be 16.`);
    }
}

// --- Modes of Operation ---

// 1. CBC Mode
function modeCBCEncrypt(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
    const padded = pkcs7Pad(plaintext);
    const output = new Uint8Array(padded.length);
    const expandedKey = keyExpansion(key);
    
    // Clone IV to avoid modifying the original reference
    let prevBlock = new Uint8Array(iv);

    for (let i = 0; i < padded.length; i += 16) {
        const block = padded.subarray(i, i + 16);
        // XOR with Previous Block (IV for first)
        const inputBlock = xorBlocks(block, prevBlock);
        // Encrypt
        const encryptedBlock = aesBlockEncrypt(inputBlock, expandedKey);
        
        output.set(encryptedBlock, i);
        prevBlock = encryptedBlock;
    }
    return output;
}

function modeCBCDecrypt(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
    if (ciphertext.length % 16 !== 0) throw new Error("Invalid ciphertext length for CBC.");
    const output = new Uint8Array(ciphertext.length);
    const expandedKey = keyExpansion(key);
    
    let prevBlock = iv;

    for (let i = 0; i < ciphertext.length; i += 16) {
        const block = ciphertext.subarray(i, i + 16);
        const decryptedBlock = aesBlockDecrypt(block, expandedKey);
        const plainBlock = xorBlocks(decryptedBlock, prevBlock);
        
        output.set(plainBlock, i);
        prevBlock = block;
    }
    
    return pkcs7Unpad(output);
}

// 2. CTR Mode
function modeCTREncrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
    const output = new Uint8Array(data.length);
    const expandedKey = keyExpansion(key);
    
    // Clone IV into a mutable counter
    const counter = new Uint8Array(iv);

    for (let i = 0; i < data.length; i += 16) {
        // 1. Encrypt the current Counter
        //    CTR generates the keystream by encrypting the counter value.
        const keyStream = aesBlockEncrypt(counter, expandedKey);
        
        // 2. XOR KeyStream with Data
        const len = Math.min(16, data.length - i);
        for (let j = 0; j < len; j++) {
            output[i + j] = data[i + j] ^ keyStream[j];
        }

        // 3. Increment Counter
        //    Standard increment treating the 16-byte block as a large integer.
        //    We start from the last byte (Big Endian increment).
        for (let k = 15; k >= 0; k--) {
            counter[k]++; 
            // If it didn't wrap around to 0, we don't need to carry to the next byte.
            if (counter[k] !== 0) break;
        }
    }
    return output;
}

// 3. OFB Mode
function modeOFBEncrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
    const output = new Uint8Array(data.length);
    const expandedKey = keyExpansion(key);
    
    // Clone IV into mutable feedback variable
    let feedback = new Uint8Array(iv);

    for (let i = 0; i < data.length; i += 16) {
        // 1. Encrypt the Feedback
        //    OFB generates keystream by encrypting the previous encryption output.
        //    (For the first block, it encrypts the IV, just like CTR).
        const keyStream = aesBlockEncrypt(feedback, expandedKey);
        
        // 2. Update Feedback for next round
        //    The output of the encryption becomes the input for the next block's encryption.
        //    We use .set() to ensure we copy the values if keyStream is reused, 
        //    though aesBlockEncrypt returns a new array.
        feedback = keyStream;

        // 3. XOR KeyStream with Data
        const len = Math.min(16, data.length - i);
        for (let j = 0; j < len; j++) {
            output[i + j] = data[i + j] ^ keyStream[j];
        }
    }
    return output;
}

// --- Padding (PKCS#7) ---

function pkcs7Pad(data: Uint8Array): Uint8Array {
    const padLen = 16 - (data.length % 16);
    const output = new Uint8Array(data.length + padLen);
    output.set(data);
    output.fill(padLen, data.length);
    return output;
}

function pkcs7Unpad(data: Uint8Array): Uint8Array {
    if (data.length === 0) return data;
    const padLen = data[data.length - 1];
    if (padLen === 0 || padLen > 16) throw new Error("Invalid PKCS#7 padding.");
    for (let i = 0; i < padLen; i++) {
        if (data[data.length - 1 - i] !== padLen) throw new Error("Invalid PKCS#7 padding bytes.");
    }
    return data.subarray(0, data.length - padLen);
}

function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(16);
    for(let i=0; i<16; i++) out[i] = a[i] ^ b[i];
    return out;
}

// --- Core AES Algorithm ---

// S-Box
const SBOX = new Uint8Array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]);

// Inverse S-Box
const INV_SBOX = new Uint8Array([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]);

const RCON = new Uint8Array([
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]);

// Key Expansion
function keyExpansion(key: Uint8Array): Uint32Array {
    const keyLen = key.length; // 16, 24, or 32
    const nb = 4; // Block size in words
    const nk = keyLen / 4; // Key length in words
    const nr = nk + 6; // Number of rounds (10, 12, 14)
    const w = new Uint32Array(nb * (nr + 1));
    
    let temp: number;

    for (let i = 0; i < nk; i++) {
        w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
    }

    for (let i = nk; i < nb * (nr + 1); i++) {
        temp = w[i - 1];
        if (i % nk === 0) {
            // RotWord
            temp = ((temp << 8) | (temp >>> 24)) >>> 0;
            // SubWord
            let t = 0;
            t |= (SBOX[(temp >>> 24) & 0xff] << 24);
            t |= (SBOX[(temp >>> 16) & 0xff] << 16);
            t |= (SBOX[(temp >>> 8) & 0xff] << 8);
            t |= (SBOX[temp & 0xff]);
            temp = t;
            // XOR Rcon
            temp ^= (RCON[(i / nk) - 1] << 24);
        } else if (nk > 6 && (i % nk === 4)) {
            // SubWord only
            let t = 0;
            t |= (SBOX[(temp >>> 24) & 0xff] << 24);
            t |= (SBOX[(temp >>> 16) & 0xff] << 16);
            t |= (SBOX[(temp >>> 8) & 0xff] << 8);
            t |= (SBOX[temp & 0xff]);
            temp = t;
        }
        w[i] = (w[i - nk] ^ temp) >>> 0;
    }
    return w;
}

// AES Encryption Block (Output strictly Uint8Array)
function aesBlockEncrypt(input: Uint8Array, w: Uint32Array): Uint8Array {
    const nb = 4;
    const nr = (w.length / nb) - 1;
    let state = new Uint32Array(4);

    for(let i=0; i<4; i++) {
        state[i] = (input[4*i] << 24) | (input[4*i+1] << 16) | (input[4*i+2] << 8) | input[4*i+3];
    }

    // AddRoundKey (Round 0)
    for(let i=0; i<4; i++) state[i] ^= w[i];

    // Rounds 1 to nr-1
    for (let round = 1; round < nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        for(let i=0; i<4; i++) state[i] ^= w[round * 4 + i];
    }

    // Final Round
    subBytes(state);
    shiftRows(state);
    for(let i=0; i<4; i++) state[i] ^= w[nr * 4 + i];

    // Convert state to output bytes
    const output = new Uint8Array(16);
    for(let i=0; i<4; i++) {
        output[4*i]   = (state[i] >>> 24) & 0xff;
        output[4*i+1] = (state[i] >>> 16) & 0xff;
        output[4*i+2] = (state[i] >>> 8)  & 0xff;
        output[4*i+3] = state[i] & 0xff;
    }
    return output;
}

// AES Decryption Block
function aesBlockDecrypt(input: Uint8Array, w: Uint32Array): Uint8Array {
    const nb = 4;
    const nr = (w.length / nb) - 1;
    let state = new Uint32Array(4);

    for(let i=0; i<4; i++) {
        state[i] = (input[4*i] << 24) | (input[4*i+1] << 16) | (input[4*i+2] << 8) | input[4*i+3];
    }

    // AddRoundKey (Round nr)
    for(let i=0; i<4; i++) state[i] ^= w[nr * 4 + i];

    // Rounds nr-1 to 1
    for (let round = nr - 1; round > 0; round--) {
        invShiftRows(state);
        invSubBytes(state);
        for(let i=0; i<4; i++) state[i] ^= w[round * 4 + i];
        invMixColumns(state);
    }

    // Initial Round
    invShiftRows(state);
    invSubBytes(state);
    for(let i=0; i<4; i++) state[i] ^= w[i];

    const output = new Uint8Array(16);
    for(let i=0; i<4; i++) {
        output[4*i]   = (state[i] >>> 24) & 0xff;
        output[4*i+1] = (state[i] >>> 16) & 0xff;
        output[4*i+2] = (state[i] >>> 8)  & 0xff;
        output[4*i+3] = state[i] & 0xff;
    }
    return output;
}

// --- Transformations ---

function subBytes(state: Uint32Array) {
    for(let i=0; i<4; i++) {
        let temp = 0;
        temp |= (SBOX[(state[i] >>> 24) & 0xff] << 24);
        temp |= (SBOX[(state[i] >>> 16) & 0xff] << 16);
        temp |= (SBOX[(state[i] >>> 8) & 0xff] << 8);
        temp |= (SBOX[state[i] & 0xff]);
        state[i] = temp >>> 0;
    }
}

function invSubBytes(state: Uint32Array) {
    for(let i=0; i<4; i++) {
        let temp = 0;
        temp |= (INV_SBOX[(state[i] >>> 24) & 0xff] << 24);
        temp |= (INV_SBOX[(state[i] >>> 16) & 0xff] << 16);
        temp |= (INV_SBOX[(state[i] >>> 8) & 0xff] << 8);
        temp |= (INV_SBOX[state[i] & 0xff]);
        state[i] = temp >>> 0;
    }
}

function shiftRows(state: Uint32Array) {
    const t0 = state[0], t1 = state[1], t2 = state[2], t3 = state[3];
    state[0] = (t0 & 0xFF000000) | (t1 & 0x00FF0000) | (t2 & 0x0000FF00) | (t3 & 0x000000FF);
    state[1] = (t1 & 0xFF000000) | (t2 & 0x00FF0000) | (t3 & 0x0000FF00) | (t0 & 0x000000FF);
    state[2] = (t2 & 0xFF000000) | (t3 & 0x00FF0000) | (t0 & 0x0000FF00) | (t1 & 0x000000FF);
    state[3] = (t3 & 0xFF000000) | (t0 & 0x00FF0000) | (t1 & 0x0000FF00) | (t2 & 0x000000FF);
}

function invShiftRows(state: Uint32Array) {
    const t0 = state[0], t1 = state[1], t2 = state[2], t3 = state[3];
    state[0] = (t0 & 0xFF000000) | (t3 & 0x00FF0000) | (t2 & 0x0000FF00) | (t1 & 0x000000FF);
    state[1] = (t1 & 0xFF000000) | (t0 & 0x00FF0000) | (t3 & 0x0000FF00) | (t2 & 0x000000FF);
    state[2] = (t2 & 0xFF000000) | (t1 & 0x00FF0000) | (t0 & 0x0000FF00) | (t3 & 0x000000FF);
    state[3] = (t3 & 0xFF000000) | (t2 & 0x00FF0000) | (t1 & 0x0000FF00) | (t0 & 0x000000FF);
}

function gmul(a: number, b: number): number {
    let p = 0;
    for (let i = 0; i < 8; i++) {
        if ((b & 1) !== 0) p ^= a;
        const hiBitSet = (a & 0x80) !== 0;
        a = (a << 1) & 0xFF;
        if (hiBitSet) a ^= 0x1B;
        b >>>= 1;
    }
    return p;
}

function mixColumns(state: Uint32Array) {
    for (let i = 0; i < 4; i++) {
        const s = state[i];
        const s0 = (s >>> 24) & 0xff;
        const s1 = (s >>> 16) & 0xff;
        const s2 = (s >>> 8) & 0xff;
        const s3 = s & 0xff;
        const d0 = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
        const d1 = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
        const d2 = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
        const d3 = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
        state[i] = ((d0 << 24) | (d1 << 16) | (d2 << 8) | d3) >>> 0;
    }
}

function invMixColumns(state: Uint32Array) {
    for (let i = 0; i < 4; i++) {
        const s = state[i];
        const s0 = (s >>> 24) & 0xff;
        const s1 = (s >>> 16) & 0xff;
        const s2 = (s >>> 8) & 0xff;
        const s3 = s & 0xff;
        const d0 = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
        const d1 = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
        const d2 = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
        const d3 = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
        state[i] = ((d0 << 24) | (d1 << 16) | (d2 << 8) | d3) >>> 0;
    }
}

// --- Util Helpers ---

function stringToUtf8Bytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

function utf8BytesToString(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
}

function bytesToBase64(buffer: ArrayBufferLike): string {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const lookup = new Uint8Array(256);
    for (let i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;
    base64 = base64.replace(/[=]+$/, '');
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
    return bytes;
}