import { Algorithm } from '../types';

export const ALGORITHMS: Algorithm[] = [
  {
    id: 'monoalphabetic',
    name: 'Monoalphabetic Cipher',
    description: 'A simple substitution cipher where each letter of the alphabet is replaced by another, using a keyword to generate the substitution alphabet.',
    category: 'symmetric',
    requiredInputs: ['key'],
  },
  {
    id: 'hill',
    name: 'Hill Cipher',
    description: 'A polygraphic substitution cipher based on linear algebra. It uses a 9-letter key to form an invertible 3x3 matrix to encrypt blocks of letters.',
    category: 'symmetric',
    requiredInputs: ['key'],
  },
  {
    id: 'columnar',
    name: 'Columnar Transposition',
    description: 'A transposition cipher that rearranges the plaintext characters into a grid and reads them off in a different order based on a keyword.',
    category: 'symmetric',
    requiredInputs: ['key'],
  },
  {
    id: 'rc4',
    name: 'RC4',
    description: 'A widely-used stream cipher. It generates a pseudorandom stream of bits (a keystream) which is XORed with the plaintext.',
    category: 'symmetric',
    requiredInputs: ['key'],
  },
  {
    id: 'aes-cbc',
    name: 'AES (CBC)',
    description: 'Advanced Encryption Standard in Cipher Block Chaining mode. Each block of plaintext is XORed with the previous ciphertext block before being encrypted.',
    category: 'symmetric',
    requiredInputs: ['key', 'iv'],
  },
  {
    id: 'aes-ofb',
    name: 'AES (OFB)',
    description: 'Advanced Encryption Standard in Output Feedback mode. Turns AES into a stream cipher by generating keystream blocks.',
    category: 'symmetric',
    requiredInputs: ['key', 'iv'],
  },
  {
    id: 'aes-ctr',
    name: 'AES (CTR)',
    description: 'Advanced Encryption Standard in Counter mode. Another method to turn a block cipher into a stream cipher, using an encrypted counter.',
    category: 'symmetric',
    requiredInputs: ['key', 'iv'],
  },
  {
    id: 'rsa',
    name: 'RSA',
    description: 'A public-key cryptosystem based on the difficulty of factoring large integers. It uses separate keys for encryption and decryption.',
    category: 'asymmetric',
    requiredInputs: ['publicKey', 'privateKey'],
  },
  {
    id: 'hmac',
    name: 'HMAC',
    description: 'Hash-based Message Authentication Code. Used to verify both the data integrity and authenticity of a message. Only provides a signature, does not encrypt.',
    category: 'symmetric',
    requiredInputs: ['key'],
  },
  {
    id: 'sha1',
    name: 'SHA-1',
    description: 'A cryptographic hash function that produces a 160-bit (20-character) hash value. Note: SHA-1 is considered insecure for most cryptographic uses.',
    category: 'keyless',
    requiredInputs: [],
  },
];
