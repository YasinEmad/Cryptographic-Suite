
import React, { useState, useEffect } from 'react';

interface MatrixInputProps {
  onChange: (matrix: string[][]) => void;
}

const MATRIX_SIZE = 3;

export const MatrixInput: React.FC<MatrixInputProps> = ({ onChange }) => {
  const [matrix, setMatrix] = useState<string[][]>(
    Array(MATRIX_SIZE).fill(null).map(() => Array(MATRIX_SIZE).fill(''))
  );

  useEffect(() => {
    onChange(matrix);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [matrix]);

  const handleInputChange = (row: number, col: number, value: string) => {
    const newMatrix = matrix.map(r => [...r]);
    const upperValue = value.toUpperCase().replace(/[^A-Z]/g, '');
    newMatrix[row][col] = upperValue.slice(-1); // Only allow one character
    setMatrix(newMatrix);
  };

  return (
    <div className="grid grid-cols-3 gap-2 w-32">
      {matrix.map((row, rowIndex) =>
        row.map((cell, colIndex) => (
          <input
            key={`${rowIndex}-${colIndex}`}
            type="text"
            value={cell}
            onChange={(e) => handleInputChange(rowIndex, colIndex, e.target.value)}
            maxLength={1}
            className="w-10 h-10 text-center bg-cyber-bg border-2 border-cyber-surface rounded-md focus:border-cyber-primary focus:outline-none focus:ring-0 text-lg font-mono"
          />
        ))
      )}
    </div>
  );
};
