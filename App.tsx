
import React from 'react';
import { Sidebar } from './components/Sidebar';
import { CryptoView } from './components/CryptoView';
import { useCrypto } from './hooks/useCrypto';
import { ALGORITHMS } from './config/algorithms.config';

function App() {
  const cryptoState = useCrypto();

  return (
    <div className="flex flex-col md:flex-row min-h-screen bg-cyber-bg text-cyber-text">
      <Sidebar
        algorithms={ALGORITHMS}
        selectedAlgorithm={cryptoState.selectedAlgorithm}
        selectAlgorithm={cryptoState.selectAlgorithm}
      />
      <main className="flex-1 p-4 md:p-8 overflow-y-auto">
        <CryptoView {...cryptoState} />
        <footer className="text-center mt-8 text-cyber-secondary text-sm">
          <p className="p-3 rounded-md bg-cyber-surface border border-cyber-surface">
            <span className="font-bold text-cyber-primary">Disclaimer:</span> This is an educational tool. Do not use it for sensitive data.
          </p>
        </footer>
      </main>
    </div>
  );
}

export default App;