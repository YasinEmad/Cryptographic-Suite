
import React, { useCallback } from 'react';
import { RequiredInput, KeyInputs } from '../types';
import { generateRsaKeyPair } from '../lib/modern/rsa';

interface KeyInputPanelProps {
  requiredInputs: RequiredInput[];
  keyInputs: KeyInputs;
  setKeyInputValue: (key: string, value: string | string[][]) => void;
  algorithmId: string;
}

const inputLabels: Record<RequiredInput, string> = {
  key: 'Key',
  iv: 'Initialization Vector (IV)',
  publicKey: 'Public Key',
  privateKey: 'Private Key',
  matrix: 'Key Matrix (3x3)',
};

const inputPlaceholders: Record<string, string> = {
    key: 'Enter your secret key',
    'hill-key': 'Enter a 9-letter key (e.g., GYBNQKURP)',
    iv: 'Enter a 16-character IV',
    publicKey: 'Paste PEM-encoded public key',
    privateKey: 'Paste PEM-encoded private key'
}

export const KeyInputPanel: React.FC<KeyInputPanelProps> = ({ requiredInputs, keyInputs, setKeyInputValue, algorithmId }) => {
  const handleGenerateRsaKeys = useCallback(async () => {
    try {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      setKeyInputValue('publicKey', publicKey);
      setKeyInputValue('privateKey', privateKey);
    } catch (e) {
      console.error("Failed to generate RSA keys", e);
      // Optionally, set an error state to show in the UI
    }
  }, [setKeyInputValue]);

  if (requiredInputs.length === 0) {
    return null;
  }

  const renderInput = (input: RequiredInput) => {
    const value = keyInputs[input] as string || '';
    switch (input) {
      case 'publicKey':
      case 'privateKey':
        return (
          <div key={input}>
            <label className="block text-sm font-bold text-cyber-secondary mb-2">{inputLabels[input]}</label>
            <textarea
              value={value}
              onChange={(e) => setKeyInputValue(input, e.target.value)}
              placeholder={inputPlaceholders[input]}
              className="w-full h-32 p-3 bg-cyber-surface rounded-md border-2 border-transparent focus:border-cyber-primary focus:outline-none focus:ring-0 transition-colors font-mono"
            />
          </div>
        );
      default:
        const placeholderKey = algorithmId === 'hill' && input === 'key' ? 'hill-key' : input;
        return (
          <div key={input}>
            <label className="block text-sm font-bold text-cyber-secondary mb-2">{inputLabels[input]}</label>
            <input
              type="text"
              value={value}
              onChange={(e) => setKeyInputValue(input, e.target.value)}
              placeholder={inputPlaceholders[placeholderKey] || inputPlaceholders.key}
              className="w-full p-3 bg-cyber-surface rounded-md border-2 border-transparent focus:border-cyber-primary focus:outline-none focus:ring-0 transition-colors font-mono"
            />
          </div>
        );
    }
  };

  return (
    <div className="p-6 bg-cyber-surface rounded-md space-y-6">
      <h3 className="text-xl font-bold text-cyber-text">Configuration</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {requiredInputs.map(renderInput)}
      </div>
      {algorithmId === 'rsa' && (
        <div className="flex justify-end">
          <button
            onClick={handleGenerateRsaKeys}
            className="px-4 py-2 border-2 border-cyber-primary text-cyber-primary font-bold rounded-md hover:bg-cyber-primary hover:text-cyber-bg transition-colors"
          >
            Generate Example Keypair
          </button>
        </div>
      )}
    </div>
  );
};