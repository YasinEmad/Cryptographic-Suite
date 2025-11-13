// This file assumes CryptoJS is loaded from a CDN and available on the window object.
declare const CryptoJS: any;

export function sha1Hash(message: string): string {
    try {
        const hash = CryptoJS.SHA1(message);
        return hash.toString(CryptoJS.enc.Hex);
    } catch (e) {
        throw new Error("SHA-1 hash generation failed.");
    }
}
