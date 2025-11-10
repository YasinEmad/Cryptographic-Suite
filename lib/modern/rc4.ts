// This file assumes CryptoJS is loaded from a CDN and available on the window object.
declare const CryptoJS: any;

export function rc4Crypt(text: string, key: string, mode: 'encrypt' | 'decrypt'): string {
    try {
        if (mode === 'encrypt') {
            const encrypted = CryptoJS.RC4.encrypt(text, key);
            return encrypted.toString();
        } else {
            const decrypted = CryptoJS.RC4.decrypt(text, key);
            const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
            if (!decryptedText) {
                // This check is crucial as CryptoJS can return an empty string for a failed decryption
                throw new Error("Decryption resulted in empty output.");
            }
            return decryptedText;
        }
    } catch (e) {
        throw new Error("RC4 decryption failed. This is likely due to an incorrect key or corrupted ciphertext.");
    }
}