
import React from 'react';

interface ToggleProps {
  labelLeft: string;
  labelRight: string;
  isChecked: boolean;
  onToggle: () => void;
}

export const Toggle: React.FC<ToggleProps> = ({ labelLeft, labelRight, isChecked, onToggle }) => {
  return (
    <div className="flex items-center space-x-3">
      <span className={`transition-colors ${!isChecked ? 'text-cyber-primary font-bold' : 'text-cyber-secondary'}`}>
        {labelLeft}
      </span>
      <button
        type="button"
        onClick={onToggle}
        className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-cyber-primary focus:ring-offset-2 focus:ring-offset-cyber-surface ${
          isChecked ? 'bg-cyber-primary' : 'bg-cyber-secondary'
        }`}
        role="switch"
        aria-checked={isChecked}
      >
        <span
          aria-hidden="true"
          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-cyber-bg shadow ring-0 transition duration-200 ease-in-out ${
            isChecked ? 'translate-x-5' : 'translate-x-0'
          }`}
        ></span>
      </button>
      <span className={`transition-colors ${isChecked ? 'text-cyber-primary font-bold' : 'text-cyber-secondary'}`}>
        {labelRight}
      </span>
    </div>
  );
};
