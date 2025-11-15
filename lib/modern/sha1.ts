function rotateLeft(n: number, s: number): number {
    return (n << s) | (n >>> (32 - s));
}

function toHexStr(n: number): string {
    let s = "";
    for (let i = 7; i >= 0; i--) {
        const v = (n >>> (i * 4)) & 0x0f;
        s += v.toString(16);
    }
    return s;
}

export function sha1Hash(msg: string): string {
    // Convert string to UTF-8 bytes
    const msgBytes: number[] = [];
    for (let i = 0; i < msg.length; i++) {
        let code = msg.charCodeAt(i);
        if (code < 0x80) {
            msgBytes.push(code);
        } else if (code < 0x800) {
            msgBytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        } else if (code < 0xd800 || code >= 0xe000) {
            msgBytes.push(
                0xe0 | (code >> 12),
                0x80 | ((code >> 6) & 0x3f),
                0x80 | (code & 0x3f)
            );
        } else {
            i++;
            code =
                0x10000 +
                (((code & 0x3ff) << 10) | (msg.charCodeAt(i) & 0x3ff));
            msgBytes.push(
                0xf0 | (code >> 18),
                0x80 | ((code >> 12) & 0x3f),
                0x80 | ((code >> 6) & 0x3f),
                0x80 | (code & 0x3f)
            );
        }
    }

    // Pre-processing
    const originalBitLength = msgBytes.length * 8;
    msgBytes.push(0x80);
    while ((msgBytes.length % 64) !== 56) {
        msgBytes.push(0x00);
    }

    const bitLenHi = Math.floor(originalBitLength / 0x100000000);
    const bitLenLo = originalBitLength >>> 0;

    msgBytes.push((bitLenHi >>> 24) & 0xff);
    msgBytes.push((bitLenHi >>> 16) & 0xff);
    msgBytes.push((bitLenHi >>> 8) & 0xff);
    msgBytes.push(bitLenHi & 0xff);
    msgBytes.push((bitLenLo >>> 24) & 0xff);
    msgBytes.push((bitLenLo >>> 16) & 0xff);
    msgBytes.push((bitLenLo >>> 8) & 0xff);
    msgBytes.push(bitLenLo & 0xff);

    // Initialize hash values
    let h0 = 0x67452301;
    let h1 = 0xefcdab89;
    let h2 = 0x98badcfe;
    let h3 = 0x10325476;
    let h4 = 0xc3d2e1f0;

    // Process each 512-bit chunk
    for (let i = 0; i < msgBytes.length; i += 64) {
        const w = new Array(80);
        for (let t = 0; t < 16; t++) {
            w[t] =
                (msgBytes[i + t * 4] << 24) |
                (msgBytes[i + t * 4 + 1] << 16) |
                (msgBytes[i + t * 4 + 2] << 8) |
                msgBytes[i + t * 4 + 3];
        }
        for (let t = 16; t < 80; t++) {
            w[t] = rotateLeft(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        }

        let a = h0;
        let b = h1;
        let c = h2;
        let d = h3;
        let e = h4;

        for (let t = 0; t < 80; t++) {
            let f: number, k: number;
            if (t < 20) {
                f = (b & c) | (~b & d);
                k = 0x5a827999;
            } else if (t < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            } else if (t < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }

            const temp = (rotateLeft(a, 5) + f + e + k + w[t]) >>> 0;
            e = d;
            d = c;
            c = rotateLeft(b, 30) >>> 0;
            b = a;
            a = temp;
        }

        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
    }

    return toHexStr(h0) + toHexStr(h1) + toHexStr(h2) + toHexStr(h3) + toHexStr(h4);
}
