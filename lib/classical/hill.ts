import { determinant3x3, modInverse, adjugate3x3 } from '../../utils/helpers';

const cleanText = (text: string) => text.toUpperCase().replace(/[^A-Z]/g, '');

const processBlock = (block: number[], matrix: number[][]): string => {
    const resultVector = [0, 0, 0];
    for (let i = 0; i < 3; i++) {
        for (let j = 0; j < 3; j++) {
            resultVector[i] += matrix[i][j] * block[j];
        }
        resultVector[i] = ((resultVector[i] % 26) + 26) % 26;
    }
    return resultVector.map(n => String.fromCharCode(n + 65)).join('');
};

const ERROR_NON_INVERTIBLE = 'Invalid key. The key must form a matrix that is mathematically invertible. Please try a different 9-letter key.';

export function hillEncrypt(plaintext: string, keyMatrix: number[][]): string {
    let text = cleanText(plaintext);
    const det = determinant3x3(keyMatrix);
    const modDet = ((det % 26) + 26) % 26;
    if (modInverse(modDet, 26) === -1) {
        throw new Error(ERROR_NON_INVERTIBLE);
    }

    while (text.length % 3 !== 0) {
        text += 'X';
    }

    let ciphertext = '';
    for (let i = 0; i < text.length; i += 3) {
        const block = [
            text.charCodeAt(i) - 65,
            text.charCodeAt(i + 1) - 65,
            text.charCodeAt(i + 2) - 65,
        ];
        ciphertext += processBlock(block, keyMatrix);
    }
    return ciphertext;
}

export function hillDecrypt(ciphertext: string, keyMatrix: number[][]): string {
    const text = cleanText(ciphertext);
    const det = determinant3x3(keyMatrix);
    const modDet = ((det % 26) + 26) % 26;
    const detInv = modInverse(modDet, 26);

    if (detInv === -1) {
        throw new Error(ERROR_NON_INVERTIBLE);
    }

    const adj = adjugate3x3(keyMatrix);
    const inverseMatrix = adj.map(row =>
        row.map(cell => (((cell * detInv) % 26) + 26) % 26)
    );
    
    let plaintext = '';
    for (let i = 0; i < text.length; i += 3) {
        const block = [
            text.charCodeAt(i) - 65,
            text.charCodeAt(i + 1) - 65,
            text.charCodeAt(i + 2) - 65,
        ];
        plaintext += processBlock(block, inverseMatrix);
    }
    return plaintext;
}