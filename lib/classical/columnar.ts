
const cleanKey = (key: string) => [...new Set(key.toUpperCase().replace(/[^A-Z]/g, ''))].join('');

export function columnarEncrypt(plaintext: string, key: string): string {
    const cKey = cleanKey(key);
    const numCols = cKey.length;
    const numRows = Math.ceil(plaintext.length / numCols);
    const paddedText = plaintext.padEnd(numRows * numCols, 'x');
    
    const grid: string[][] = [];
    for (let i = 0; i < numRows; i++) {
        grid.push(paddedText.slice(i * numCols, (i + 1) * numCols).split(''));
    }

    const sortedKey = cKey.split('').map((char, index) => ({ char, index })).sort((a, b) => a.char.localeCompare(b.char));
    
    let ciphertext = '';
    for (const { index } of sortedKey) {
        for (let row = 0; row < numRows; row++) {
            ciphertext += grid[row][index];
        }
    }
    
    return ciphertext;
}

export function columnarDecrypt(ciphertext: string, key: string): string {
    const cKey = cleanKey(key);
    const numCols = cKey.length;
    const numRows = Math.ceil(ciphertext.length / numCols);
    
    if (ciphertext.length !== numCols * numRows) {
        throw new Error('Invalid ciphertext length for the given key.');
    }
    
    const sortedKey = cKey.split('').map((char, index) => ({ char, index })).sort((a, b) => a.char.localeCompare(b.char));
    
    const grid: string[][] = Array(numRows).fill(null).map(() => Array(numCols).fill(''));
    let cipherIndex = 0;

    for (const { index } of sortedKey) {
        for (let row = 0; row < numRows; row++) {
            grid[row][index] = ciphertext[cipherIndex++];
        }
    }

    return grid.map(row => row.join('')).join('');
}
