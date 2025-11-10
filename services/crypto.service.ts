import { CryptoMode, KeyInputs } from '../types';
import { monoalphabeticEncrypt, monoalphabeticDecrypt } from '../lib/classical/monoalphabetic';
import { hillEncrypt, hillDecrypt } from '../lib/classical/hill';
import { columnarEncrypt, columnarDecrypt } from '../lib/classical/columnar';
import { rc4Crypt } from '../lib/modern/rc4';
import { aesEncrypt, aesDecrypt } from '../lib/modern/aes';
import { rsaEncrypt, rsaDecrypt } from '../lib/modern/rsa';
import { hmacSign } from '../lib/modern/hmac';

const keyToMatrix = (key: string): number[][] => {
    const matrix: number[][] = [[], [], []];
    for (let i = 0; i < 9; i++) {
        matrix[Math.floor(i / 3)][i % 3] = key.charCodeAt(i) - 65;
    }
    return matrix;
};

export async function executeCrypto(
  algorithmId: string,
  mode: CryptoMode,
  text: string,
  inputs: KeyInputs
): Promise<string> {

  if (!text) {
    throw new Error('Input text cannot be empty.');
  }

  switch (algorithmId) {
    case 'monoalphabetic':
      if (!inputs.key || typeof inputs.key !== 'string') throw new Error('A string key is required.');
      return mode === 'encrypt' ? monoalphabeticEncrypt(text, inputs.key) : monoalphabeticDecrypt(text, inputs.key);
    
    case 'hill':
      if (!inputs.key || typeof inputs.key !== 'string') throw new Error('A string key is required.');
      if (!/^[a-zA-Z]{9}$/.test(inputs.key)) {
        throw new Error('Hill Cipher key must be exactly 9 alphabetic characters.');
      }
      const matrixKey = keyToMatrix(inputs.key.toUpperCase());
      return mode === 'encrypt' ? hillEncrypt(text, matrixKey) : hillDecrypt(text, matrixKey);

    case 'columnar':
      if (!inputs.key || typeof inputs.key !== 'string') throw new Error('A string key is required.');
      return mode === 'encrypt' ? columnarEncrypt(text, inputs.key) : columnarDecrypt(text, inputs.key);

    case 'rc4':
      if (!inputs.key || typeof inputs.key !== 'string') throw new Error('A string key is required.');
      // RC4 is symmetric, encryption and decryption are the same operation.
      return rc4Crypt(text, inputs.key, mode);

    case 'aes-cbc':
    case 'aes-ofb':
    case 'aes-ctr':
      if (!inputs.key || typeof inputs.key !== 'string' || inputs.key.length === 0) throw new Error('A non-empty string key is required.');
      if (![16, 24, 32].includes(inputs.key.length)) {
        throw new Error('AES key must be exactly 16, 24, or 32 characters long (for 128, 192, or 256-bit keys respectively).');
      }
      if (!inputs.iv || typeof inputs.iv !== 'string') throw new Error('A string Initialization Vector (IV) is required.');
      if (inputs.iv.length !== 16) {
        throw new Error('For AES, the Initialization Vector (IV) must be exactly 16 characters long.');
      }
      const modeName = algorithmId.split('-')[1].toUpperCase();
      return mode === 'encrypt' ? aesEncrypt(text, inputs.key, inputs.iv, modeName) : aesDecrypt(text, inputs.key, inputs.iv, modeName);
    
    case 'rsa':
      if (mode === 'encrypt') {
        if (!inputs.publicKey || typeof inputs.publicKey !== 'string') throw new Error('A public key is required for encryption.');
        return rsaEncrypt(text, inputs.publicKey);
      } else {
        if (!inputs.privateKey || typeof inputs.privateKey !== 'string') throw new Error('A private key is required for decryption.');
        return rsaDecrypt(text, inputs.privateKey);
      }

    case 'hmac':
       if (!inputs.key || typeof inputs.key !== 'string') throw new Error('A string key is required.');
      if (mode === 'decrypt') {
        return "HMAC is a one-way signature algorithm. 'Decryption' is not applicable. Run in 'Encrypt' mode to generate a new signature.";
      }
      return hmacSign(text, inputs.key);

    default:
      throw new Error(`Algorithm '${algorithmId}' is not implemented.`);
  }
}