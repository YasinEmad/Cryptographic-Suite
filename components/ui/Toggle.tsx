
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
      <span className={`transition-colors ${!isChecked ? 'text-brand-primary font-bold' : 'text-brand-secondary'}`}>
        {labelLeft}
      </span>
      <button
        type="button"
        onClick={onToggle}
        className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-brand-primary focus:ring-offset-2 focus:ring-offset-brand-surface ${
          isChecked ? 'bg-brand-primary' : 'bg-brand-secondary'
        }`}
        role="switch"
        aria-checked={isChecked}
      >
        <span
          aria-hidden="true"
          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-brand-text shadow ring-0 transition duration-200 ease-in-out ${
            isChecked ? 'translate-x-5' : 'translate-x-0'
          }`}
        ></span>
      </button>
      <span className={`transition-colors ${isChecked ? 'text-brand-primary font-bold' : 'text-brand-secondary'}`}>
        {labelRight}
      </span>
    </div>
  );
};