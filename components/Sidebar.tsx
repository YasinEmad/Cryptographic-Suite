
import React from 'react';
import { Algorithm, AlgorithmCategory } from '../types';

interface SidebarProps {
  algorithms: Algorithm[];
  selectedAlgorithm: Algorithm;
  selectAlgorithm: (algorithm: Algorithm) => void;
}

const CategoryTitle: React.FC<{ title: string, icon: React.ReactNode }> = ({ title, icon }) => (
  <div className="flex items-center gap-3 px-4 my-4">
    {icon}
    <h2 className="text-sm font-bold text-cyber-secondary uppercase tracking-widest">
      {title}
    </h2>
  </div>
);

const AlgorithmButton: React.FC<{ algorithm: Algorithm; isSelected: boolean; onClick: () => void; }> = ({ algorithm, isSelected, onClick }) => (
  <button
    onClick={onClick}
    className={`w-full text-left py-2 rounded-r-md transition-colors duration-200 ${
      isSelected
        ? 'bg-cyber-primary/10 text-cyber-primary border-l-4 border-cyber-primary pl-3 pr-4'
        : 'text-cyber-secondary hover:bg-cyber-surface hover:text-cyber-text pl-4 pr-4'
    }`}
  >
    {algorithm.name}
  </button>
);

export const Sidebar: React.FC<SidebarProps> = ({ algorithms, selectedAlgorithm, selectAlgorithm }) => {
  const renderCategory = (category: AlgorithmCategory, title: string, icon: React.ReactNode) => (
    <div>
      <CategoryTitle title={title} icon={icon} />
      <div className="space-y-1">
        {algorithms
          .filter(a => a.category === category)
          .map(algo => (
            <AlgorithmButton
              key={algo.id}
              algorithm={algo}
              isSelected={selectedAlgorithm.id === algo.id}
              onClick={() => selectAlgorithm(algo)}
            />
          ))}
      </div>
    </div>
  );

  return (
    <aside className="w-full md:w-64 bg-cyber-bg md:bg-cyber-surface/30 p-4 border-b-2 md:border-b-0 md:border-r-2 border-cyber-surface flex-shrink-0">
      <h1 className="text-lg font-bold text-cyber-primary mb-6 px-4">Cryptographic Suite</h1>
      <nav>
        {renderCategory('classical', 'Classical', 
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-cyber-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
          </svg>
        )}
        {renderCategory('modern', 'Modern',
           <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-cyber-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
             <path strokeLinecap="round" strokeLinejoin="round" d="M12 11c0 3.517-1.009 6.789-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-1.026.977-2.206.977-3.468a9 9 0 00-18 0c0 1.262.332 2.442.977 3.468l3.838-1.132zM12 6V5a1 1 0 00-1-1H9a1 1 0 00-1 1v1h4z" />
           </svg>
        )}
      </nav>
    </aside>
  );
};