# Cryptographic Suite: An Interactive Learning Tool

This project is a web-based educational sandbox for encrypting and decrypting text using a wide variety of classical and modern cryptographic algorithms. It's designed to visually demonstrate how each algorithm works in an interactive and user-friendly environment.

## How to Run

This project uses **Vite**, **React**, and **TypeScript**. Follow these steps to run it locally:

1. **Clone the repository**
```bash
git clone https://github.com/YasinEmad/Cryptographic-Suite.git
cd Cryptographic-Suite

    Install dependencies 

npm install

    Start the development server

npm run dev

## ✨ Features

- **Wide Range of Algorithms**: Implements classical, symmetric, asymmetric, and keyless (hashing) algorithms.
- **Interactive Interface**: A clean, modern UI for entering text, keys, and other parameters, with instant results.
- **Algorithm Descriptions**: Each algorithm includes a brief, easy-to-understand description of its principles.
- **Dynamic UI**: The interface adapts to the selected algorithm, only showing the necessary input fields (e.g., Key, IV, Public/Private Keys).
- **Real-time RSA Key Generation**: Generate 2048-bit RSA key pairs directly in the browser.
- **Responsive Design**: Fully usable on both desktop and mobile devices.
- **Copy to Clipboard**: Easily copy the output ciphertext or hash.
- **Error Handling**: Provides clear error messages for common issues like incorrect key lengths or invalid ciphertext.
- **Zero Build Setup**: Runs directly in the browser using modern web standards, with no `npm install` or build step required.

## 🚀 Live Demo

This application is designed to run in a web-based development environment. Simply load the files into a static file server to see it in action.

## 🛠️ Technology Stack

- **Frontend**:
  - [**React**](https://react.dev/): A JavaScript library for building user interfaces.
  - [**TypeScript**](https://www.typescriptlang.org/): A typed superset of JavaScript that compiles to plain JavaScript.
  - [**Tailwind CSS**](https://tailwindcss.com/): A utility-first CSS framework for rapid UI development.
- **Cryptography Libraries (via CDN)**:
  - [**CryptoJS**](https://cryptojs.gitbook.io/docs): Used for a variety of modern algorithms like AES, RC4, HMAC, and SHA-1.
  - [**Forge**](https://github.com/digitalbazaar/forge): A native implementation of TLS in JavaScript, used here for its robust RSA implementation.

## 📂 Project Structure

The project is organized into logical directories to separate concerns:

```
.
├── App.tsx               # Main application component, orchestrates layout and state.
├── index.html            # The single HTML entry point, loads CDNs and scripts.
├── index.tsx             # Renders the React application into the DOM.
├── metadata.json         # Project metadata.
├── types.ts              # Contains all TypeScript type definitions.
│
├── components/           # Reusable React components.
│   ├── ui/               # Generic UI elements (Toggle, CopyButton, etc.).
│   ├── CryptoView.tsx    # Main view for input/output and controls.
│   ├── KeyInputPanel.tsx # Panel for key/IV/parameter inputs.
│   └── Sidebar.tsx       # Navigation sidebar for selecting algorithms.
│
├── config/               # Application configuration.
│   └── algorithms.config.ts # Defines all supported algorithms and their properties.
│
├── hooks/                # Custom React hooks.
│   └── useCrypto.ts      # Manages all cryptographic state and logic orchestration.
│
├── lib/                  # Core cryptographic algorithm implementations.
│   ├── classical/        # Implementations of classical ciphers.
│   └── modern/           # Wrappers for modern crypto libraries (CryptoJS, Forge).
│
├── services/
│   └── crypto.service.ts # A service layer that acts as a router to the correct crypto function.
│
└── utils/
    └── helpers.ts        # Utility functions (e.g., matrix math for Hill Cipher).
```

## 🧠 How It Works

The application's logic flows from user interaction in the UI down to the specific cryptographic implementation.

1.  **UI Interaction (`Sidebar.tsx`, `CryptoView.tsx`)**: The user selects an algorithm from the sidebar. The main view updates to reflect this choice.
2.  **State Management (`useCrypto.ts`)**: This central hook holds the entire state of the application: the selected algorithm, input/output text, keys, mode (encrypt/decrypt), and loading/error status. When the user changes an input or selects a new algorithm, this hook updates the state.
3.  **Execution Trigger**: Clicking the "Run" / "Hash" button calls the `runCrypto` function from the `useCrypto` hook.
4.  **Service Layer (`crypto.service.ts`)**: The `runCrypto` function calls `executeCrypto`, passing the current state. This service acts as a controller, using a `switch` statement on the `algorithmId` to delegate the task to the appropriate function in the `lib/` directory. It also performs initial validation.
5.  **Cryptography Library (`lib/`)**: This is where the actual cryptographic operations happen.
    -   Classical ciphers (`monoalphabetic.ts`, `hill.ts`) are implemented in pure TypeScript.
    -   Modern algorithms (`aes.ts`, `rsa.ts`, `sha1.ts`) are wrappers around the `CryptoJS` and `forge` libraries, which are available globally from the CDN scripts loaded in `index.html`.
6.  **Result Propagation**: The result (or an error) from the `lib/` function is passed back up through the service layer to the `useCrypto` hook, which updates the state. React then re-renders the `CryptoView` to display the output or error message.

## 📜 Algorithms Implemented

#### Symmetric (Single Key)
- **Monoalphabetic Cipher**: A classical substitution cipher.
- **Hill Cipher**: A classical polygraphic cipher using linear algebra.
- **Columnar Transposition**: A classical transposition cipher.
- **RC4**: A modern stream cipher.
- **AES (CBC, OFB, CTR)**: The Advanced Encryption Standard in three common modes of operation.
- **HMAC**: Hash-based Message Authentication Code for data integrity and authenticity.

#### Asymmetric (Two Keys)
- **RSA**: A widely-used public-key cryptosystem. Supports in-browser key generation.

#### Keyless (Hashing)
- **SHA-1**: A cryptographic hash function (Note: Included for educational purposes; considered insecure for most modern uses).

---

> **Disclaimer**: This is an educational tool. Do not use it for sensitive data. The cryptographic implementations are for demonstration purposes and may not be secure against all forms of attack.
