
````markdown
# Cryptographic Suite: An Interactive Learning Tool

This project is a web-based educational sandbox for encrypting and decrypting text using a wide variety of classical and modern cryptographic algorithms. It visually demonstrates how each algorithm works in an interactive and user-friendly environment.

## Features

- **Wide Range of Algorithms**: Implements classical, symmetric, asymmetric, and keyless (hashing) algorithms.
- **Interactive Interface**: Enter text, keys, and parameters with instant results.
- **Algorithm Descriptions**: Each algorithm has a brief, easy-to-understand explanation.
- **Dynamic UI**: Only shows input fields required for the selected algorithm.
- **Real-time RSA Key Generation**: Generate 2048-bit RSA key pairs in the browser.
- **Responsive Design**: Works on both desktop and mobile devices.
- **Copy to Clipboard**: Easily copy ciphertext or hash results.
- **Error Handling**: Displays clear error messages for invalid keys or ciphertext.

## How to Run

This project uses **Vite**, **React**, and **TypeScript**. To run it locally:

1. **Clone the repository**
```bash
git clone https://github.com/YasinEmad/Cryptographic-Suite.git
cd Cryptographic-Suite
````

2. **Install dependencies**

```bash
npm install
```

3. **Start the development server**

```bash
npm run dev
```

4. **Open in browser**
   Vite will show a local URL (usually `http://localhost:5173`). Open it to see the app.

5. **Build for production (optional)**

```bash
npm run build
```

The build files will be in the `dist/` folder, ready to deploy.

> Note: This project loads **CryptoJS** and **Forge** via CDN, so you need an internet connection for cryptography features.

## Technology Stack

* **Frontend**: React, TypeScript, Tailwind CSS
* **Cryptography Libraries**:

  * **CryptoJS**: AES, RC4, HMAC, SHA-1
  * **Forge**: RSA key generation and encryption

## Project Structure

```
.
├── App.tsx               # Main component
├── index.html            # Single HTML entry point
├── index.tsx             # Renders React app
├── metadata.json         # Project metadata
├── types.ts              # TypeScript types
├── components/           # Reusable React components
│   ├── ui/               # Generic UI elements
│   ├── CryptoView.tsx    # Input/output controls
│   ├── KeyInputPanel.tsx # Key/IV input panel
│   └── Sidebar.tsx       # Algorithm selector
├── config/
│   └── algorithms.config.ts # Supported algorithms
├── hooks/
│   └── useCrypto.ts      # Central state & crypto logic
├── lib/
│   ├── classical/        # Classical cipher implementations
│   └── modern/           # Wrappers for CryptoJS & Forge
├── services/
│   └── crypto.service.ts # Routes to correct crypto function
└── utils/
    └── helpers.ts        # Utility functions (e.g., Hill cipher math)
```

## How It Works

1. **UI Interaction**: User selects algorithm and enters text/keys.
2. **State Management**: `useCrypto` hook holds the state for algorithm, text, keys, mode, and errors.
3. **Execution**: Clicking "Run" or "Hash" triggers `runCrypto`.
4. **Service Layer**: `crypto.service.ts` routes the request to the correct function in `lib/`.
5. **Cryptography Layer**:

   * Classical ciphers are implemented in TypeScript.
   * Modern algorithms use CryptoJS or Forge loaded via CDN.
6. **Result Propagation**: Output or error is returned to the UI for display.

## Algorithms Implemented

**Symmetric (Single Key)**

* Monoalphabetic Cipher
* Hill Cipher
* Columnar Transposition
* RC4
* AES (CBC, OFB, CTR)
* HMAC

**Asymmetric (Two Keys)**

* RSA (2048-bit key support)

**Keyless (Hashing)**

* SHA-1 (for educational purposes)

> Disclaimer: This is an educational tool. Do not use it for sensitive data. Implementations are for demonstration and may not be secure.

## Live Demo

[cryptographic-suite.vercel.app](https://cryptographic-suite.vercel.app)

```


