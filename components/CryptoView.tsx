
import React from 'react';
import { UseCryptoReturn } from '../hooks/useCrypto';
import { Toggle } from './ui/Toggle';
import { CopyButton } from './ui/CopyButton';
import { KeyInputPanel } from './KeyInputPanel';

type CryptoViewProps = UseCryptoReturn;

export const CryptoView: React.FC<CryptoViewProps> = ({
  selectedAlgorithm,
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
}) => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-cyber-primary">{selectedAlgorithm.name}</h1>
        <p className="text-cyber-secondary mt-2">{selectedAlgorithm.description}</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
           <label className="block text-sm font-bold text-cyber-secondary mb-2">Input / Plaintext</label>
           <textarea
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Enter text to process..."
            className="w-full h-48 p-3 bg-cyber-surface rounded-md border-2 border-transparent focus:border-cyber-primary focus:outline-none focus:ring-0 transition-colors font-mono"
          />
        </div>
        <div className="relative">
          <label className="block text-sm font-bold text-cyber-secondary mb-2">Output / Ciphertext</label>
          <textarea
            value={outputText}
            readOnly
            placeholder="Result will appear here..."
            className="w-full h-48 p-3 bg-cyber-surface rounded-md border-2 border-transparent font-mono"
          />
          {outputText && <CopyButton textToCopy={outputText} />}
        </div>
      </div>

      {error && (
          <div className="p-3 bg-cyber-error/20 text-cyber-error border border-cyber-error/50 rounded-md">
              <p><span className="font-bold">Error:</span> {error}</p>
          </div>
      )}

      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 bg-cyber-surface rounded-md">
        <div className="flex items-center gap-4">
          <span className="font-bold text-cyber-secondary">Mode:</span>
          <Toggle
            labelLeft="Encrypt"
            labelRight="Decrypt"
            isChecked={mode === 'decrypt'}
            onToggle={() => setMode(prev => (prev === 'encrypt' ? 'decrypt' : 'encrypt'))}
          />
        </div>
        <button
          onClick={runCrypto}
          disabled={isLoading}
          className="w-full sm:w-auto px-8 py-3 bg-cyber-primary text-cyber-bg font-bold rounded-md hover:opacity-90 transition-all duration-200 disabled:bg-cyber-secondary disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {isLoading ? (
            <>
              <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-cyber-bg" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Processing...
            </>
          ) : (
            <>
              <span>Run</span>
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clipRule="evenodd" />
              </svg>
            </>
          )}
        </button>
      </div>
      
      <KeyInputPanel
        requiredInputs={selectedAlgorithm.requiredInputs}
        keyInputs={keyInputs}
        setKeyInputValue={setKeyInputValue}
        algorithmId={selectedAlgorithm.id}
      />
    </div>
  );
};