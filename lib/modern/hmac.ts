
// This file assumes CryptoJS is loaded from a CDN and available on the window object.
declare const CryptoJS: any;

export function hmacSign(message: string, key: string): string {
    try {
        const signature = CryptoJS.HmacSHA256(message, key);
        return signature.toString(CryptoJS.enc.Hex);
    } catch (e) {
        throw new Error("HMAC signature generation failed.");
    }
}
