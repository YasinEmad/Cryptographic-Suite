const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

function generateCipherAlphabet(key: string): string {
    const keyUpper = key.toUpperCase().replace(/[^A-Z]/g, '');
    const uniqueChars = [...new Set(keyUpper.split(''))];
    const remainingChars = ALPHABET.split('').filter(char => !uniqueChars.includes(char));
    return [...uniqueChars, ...remainingChars].join('');
}

export function monoalphabeticEncrypt(plaintext: string, key: string): string {
    const cipherAlphabet = generateCipherAlphabet(key);
    let ciphertext = '';
    for (const char of plaintext) {
        const upperChar = char.toUpperCase();
        const index = ALPHABET.indexOf(upperChar);
        if (index !== -1) {
            const isLowerCase = char === char.toLowerCase();
            const encryptedChar = cipherAlphabet[index];
            ciphertext += isLowerCase ? encryptedChar.toLowerCase() : encryptedChar;
        } else {
            ciphertext += char;
        }
    }
    return ciphertext;
}

export function monoalphabeticDecrypt(ciphertext: string, key: string): string {
    const cipherAlphabet = generateCipherAlphabet(key);
    let plaintext = '';
    for (const char of ciphertext) {
        const upperChar = char.toUpperCase();
        const index = cipherAlphabet.indexOf(upperChar);
        if (index !== -1) {
            const isLowerCase = char === char.toLowerCase();
            const decryptedChar = ALPHABET[index];
            plaintext += isLowerCase ? decryptedChar.toLowerCase() : decryptedChar;
        } else {
            plaintext += char;
        }
    }
    return plaintext;
}