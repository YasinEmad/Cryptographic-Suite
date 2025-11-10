// This file assumes CryptoJS is loaded from a CDN and available on the window object.
declare const CryptoJS: any;

const getModeConfig = (modeName: string) => {
    switch (modeName) {
        case 'CBC':
            return CryptoJS.mode.CBC;
        case 'OFB':
            return CryptoJS.mode.OFB;
        case 'CTR':
            return CryptoJS.mode.CTR;
        default:
            throw new Error(`Unsupported AES mode: ${modeName}`);
    }
}

export function aesEncrypt(plaintext: string, key: string, iv: string, modeName: string): string {
    const parsedKey = CryptoJS.enc.Utf8.parse(key);
    const parsedIv = CryptoJS.enc.Utf8.parse(iv);
    
    const encrypted = CryptoJS.AES.encrypt(plaintext, parsedKey, {
        iv: parsedIv,
        mode: getModeConfig(modeName),
        padding: CryptoJS.pad.Pkcs7
    });

    return encrypted.toString();
}

export function aesDecrypt(ciphertext: string, key: string, iv: string, modeName: string): string {
    const parsedKey = CryptoJS.enc.Utf8.parse(key);
    const parsedIv = CryptoJS.enc.Utf8.parse(iv);

    try {
        const decrypted = CryptoJS.AES.decrypt(ciphertext, parsedKey, {
            iv: parsedIv,
            mode: getModeConfig(modeName),
            padding: CryptoJS.pad.Pkcs7
        });
        
        const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
        if (!decryptedText) {
             // CryptoJS may return an empty string on failure.
            throw new Error("Decryption produced no output.");
        }
        return decryptedText;
    } catch (e) {
        throw new Error("AES decryption failed. Please verify the key, IV, mode, and ciphertext are all correct. The data may be corrupted.");
    }
}