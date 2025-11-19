/**
 * RC4 Encryption/Decryption Implementation from Scratch
 * Replaces browser-specific 'window.btoa'/'window.atob' with custom helpers.
 */

export function rc4Crypt(text: string, key: string, mode: 'encrypt' | 'decrypt'): string {
    try {
        const keyBytes = stringToUtf8Bytes(key);
        
        if (mode === 'encrypt') {
            // 1. Convert Plaintext to Bytes (UTF-8)
            const dataBytes = stringToUtf8Bytes(text);
            // 2. Apply RC4 (XOR)
            const cipherBytes = rc4(keyBytes, dataBytes);
            // 3. Convert to Base64
            return bytesToBase64(cipherBytes);
        } else {
            // 1. Convert Base64 Ciphertext to Bytes
            const dataBytes = base64ToBytes(text);
            // 2. Apply RC4 (XOR) - It's symmetric
            const plainBytes = rc4(keyBytes, dataBytes);
            // 3. Convert Bytes back to UTF-8 String
            const decryptedText = utf8BytesToString(plainBytes);
            
            if (!decryptedText && plainBytes.length > 0) {
                throw new Error("Decryption resulted in invalid UTF-8 output.");
            }
            return decryptedText;
        }
    } catch (e) {
        throw new Error("RC4 operation failed. Ensure key and input format are correct.");
    }
}

/**
 * The Core RC4 Algorithm
 */
function rc4(key: Uint8Array, input: Uint8Array): Uint8Array {
    // 1. Initialize S-Box (State)
    const s = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
        s[i] = i;
    }

    // 2. Key-Scheduling Algorithm (KSA)
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % key.length]) % 256;
        // Swap
        [s[i], s[j]] = [s[j], s[i]];
    }

    // 3. Pseudo-Random Generation Algorithm (PRGA) & XOR
    const output = new Uint8Array(input.length);
    let i = 0;
    j = 0;
    
    for (let k = 0; k < input.length; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        
        // Swap
        [s[i], s[j]] = [s[j], s[i]];
        
        // Generate Key Stream Byte
        const keyStreamByte = s[(s[i] + s[j]) % 256];
        
        // XOR with Input
        output[k] = input[k] ^ keyStreamByte;
    }

    return output;
}

// --- Helper Functions for Encoding ---

function stringToUtf8Bytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

function utf8BytesToString(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
}

// --- Custom Base64 Helpers (No 'window' dependency) ---

function bytesToBase64(buffer: Uint8Array): string {
  let binary = "";
  const len = buffer.byteLength;
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
  for (let i = 0; i < len; i += 3) {
      const b1 = buffer[i];
      const b2 = i + 1 < len ? buffer[i + 1] : 0;
      const b3 = i + 2 < len ? buffer[i + 2] : 0;
      
      const e1 = b1 >> 2;
      const e2 = ((b1 & 3) << 4) | (b2 >> 4);
      const e3 = ((b2 & 15) << 2) | (b3 >> 6);
      const e4 = b3 & 63;
      
      binary += chars.charAt(e1) + chars.charAt(e2);
      binary += (i + 1 < len) ? chars.charAt(e3) : "=";
      binary += (i + 2 < len) ? chars.charAt(e4) : "=";
  }
  return binary;
}

function base64ToBytes(base64: string): Uint8Array {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const lookup = new Uint8Array(256);
  for (let i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;
  
  base64 = base64.replace(/[=]+$/, ''); // Remove padding
  const len = base64.length;
  let bufferLength = len * 0.75;
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