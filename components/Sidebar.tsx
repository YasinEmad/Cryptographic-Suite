
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
    <h2 className="text-sm font-bold text-brand-secondary uppercase tracking-widest">
      {title}
    </h2>
  </div>
);

const AlgorithmButton: React.FC<{ algorithm: Algorithm; isSelected: boolean; onClick: () => void; }> = ({ algorithm, isSelected, onClick }) => (
  <button
    onClick={onClick}
    className={`w-full text-left py-2 rounded-r-md transition-colors duration-200 ${
      isSelected
        ? 'bg-brand-primary/10 text-brand-primary border-l-4 border-brand-primary pl-3 pr-4'
        : 'text-brand-secondary hover:bg-brand-bg hover:text-brand-text pl-4 pr-4'
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
    <aside className="w-full md:w-64 bg-brand-surface p-4 border-b-2 md:border-b-0 md:border-r-2 border-brand-bg flex-shrink-0">
      <h1 className="text-lg font-bold text-brand-primary mb-6 px-4">Cryptographic Suite</h1>
      <nav>
        {renderCategory('symmetric', 'Symmetric (Single Key)', 
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-brand-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
          </svg>
        )}
        {renderCategory('asymmetric', 'Asymmetric (Two Keys)',
           <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-brand-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
             <path strokeLinecap="round" strokeLinejoin="round" d="M15 9h3.75M15 12h3.75M15 15h3.75M4.5 19.5h15a2.25 2.25 0 002.25-2.25V6.75A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25v10.5A2.25 2.25 0 004.5 19.5zm6-10.125a1.875 1.875 0 11-3.75 0 1.875 1.875 0 013.75 0zm-3.75 0h.008v.015h-.008V9.375z" />
           </svg>
        )}
        {renderCategory('keyless', 'Keyless (Hashing)',
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-brand-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14" />
          </svg>
        )}
      </nav>
    </aside>
  );
};
