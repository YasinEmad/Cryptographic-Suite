
// This file assumes node-forge is loaded from a CDN and available on the window object.
declare const forge: any;

export async function generateRsaKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (err: any, keypair: any) => {
      if (err) {
        reject(err);
      } else {
        resolve({
          publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
          privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
        });
      }
    });
  });
}

export function rsaEncrypt(plaintext: string, publicKeyPem: string): string {
    try {
        const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
        const encrypted = publicKey.encrypt(plaintext, 'RSA-OAEP', {
            md: forge.md.sha256.create()
        });
        return forge.util.encode64(encrypted);
    } catch (e) {
        throw new Error("RSA encryption failed. Ensure the public key is valid and in PEM format.");
    }
}

export function rsaDecrypt(ciphertext: string, privateKeyPem: string): string {
    try {
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        const decodedCiphertext = forge.util.decode64(ciphertext);
        const decrypted = privateKey.decrypt(decodedCiphertext, 'RSA-OAEP', {
            md: forge.md.sha256.create()
        });
        return decrypted;
    } catch (e) {
        throw new Error("RSA decryption failed. Ensure the private key is correct and the ciphertext is valid.");
    }
}
