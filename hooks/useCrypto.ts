
import { useState, useCallback } from 'react';
import { Algorithm, CryptoMode, KeyInputs } from '../types';
import { ALGORITHMS } from '../config/algorithms.config';
import { executeCrypto } from '../services/crypto.service';

export const useCrypto = () => {
  const [selectedAlgorithm, setSelectedAlgorithm] = useState<Algorithm>(ALGORITHMS[0]);
  const [mode, setMode] = useState<CryptoMode>('encrypt');
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [keyInputs, setKeyInputs] = useState<KeyInputs>({});
  const [isLoading, setIsLoading] = useState(false);

  const selectAlgorithm = useCallback((algorithm: Algorithm) => {
    setSelectedAlgorithm(algorithm);
    setInputText('');
    setOutputText('');
    setError(null);
    setKeyInputs({});
  }, []);

  const setKeyInputValue = useCallback((key: string, value: string | string[][]) => {
    setKeyInputs(prev => ({ ...prev, [key]: value }));
  }, []);

  const runCrypto = useCallback(async () => {
    setError(null);
    setOutputText('');
    setIsLoading(true);

    // For RSA, use the public key for encryption and private key for decryption
    let activeKeyInputs = { ...keyInputs };
    if (selectedAlgorithm.id === 'rsa') {
      if (mode === 'encrypt') {
        activeKeyInputs = { publicKey: keyInputs.publicKey };
      } else {
        activeKeyInputs = { privateKey: keyInputs.privateKey };
      }
    }


    try {
        const result = await executeCrypto(selectedAlgorithm.id, mode, inputText, activeKeyInputs);
        setOutputText(result);
    } catch (e: any) {
        setError(e.message || 'An unknown error occurred.');
    } finally {
        setIsLoading(false);
    }
  }, [selectedAlgorithm, mode, inputText, keyInputs]);

  return {
    selectedAlgorithm,
    selectAlgorithm,
    mode,
    setMode,
    inputText,
    setInputText,
    outputText,
    error,
    keyInputs,
    setKeyInputValue,
    runCrypto,
    isLoading
  };
};

export type UseCryptoReturn = ReturnType<typeof useCrypto>;
