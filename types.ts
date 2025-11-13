
export type AlgorithmCategory = 'symmetric' | 'asymmetric' | 'keyless';
export type CryptoMode = 'encrypt' | 'decrypt';
export type RequiredInput = 'key' | 'iv' | 'publicKey' | 'privateKey' | 'matrix';

export interface Algorithm {
  id: string;
  name: string;
  description: string;
  category: AlgorithmCategory;
  requiredInputs: RequiredInput[];
}

export interface KeyInputs {
  [key: string]: string | string[][];
}
