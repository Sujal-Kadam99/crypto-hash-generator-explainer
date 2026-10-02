# Crypto Hash Generator & Explainer

**An educational, real-time cryptographic hash generator and visual explainer.**

![Crypto Hash Generator & Explainer Screenshot Placeholder](placeholder-screenshot.png)

## Overview

Crypto Hash Generator & Explainer is a local, bit-accurate cryptographic hash engine and visual explainer. It computes MD5, SHA-1, SHA-256, and SHA-512 hashes instantly using pure JavaScript, without any external dependencies. It's designed to help developers and students intuitively understand how hashing functions, the avalanche effect, and the block-round math work under the hood.

> ⚠️ **EDUCATIONAL AND AUTHORIZED USE ONLY**
> This tool provides pure-JavaScript implementations of hashing algorithms strictly for educational and visualization purposes. 
> - **MD5 and SHA-1 are cryptographically broken** and vulnerable to collision attacks. They must never be used for security applications.
> - **Raw hashes (like SHA-256) are not safe for password hashing**. Use key-stretching algorithms like Argon2id or bcrypt for storing passwords.
> - **Never use these implementations for production crypto**. They are designed for readability and education, not constant-time execution or side-channel resistance.

## Tech Stack
- **Frontend**: Vanilla JavaScript (ES2022+), HTML5, CSS3.
- **Backend / Tests**: Node.js (for the static server and test runner).
- **Dependencies**: None. Zero external packages.

## Architecture
Crypto Hash Generator & Explainer uses a monolithic, zero-dependency architecture for the main application (`hash_tool.js`), which contains bitwise implementations of all cryptographic algorithms, alongside DOM manipulation logic to render the visual explainer tabs dynamically. It runs locally in the browser. A tiny Node.js static server (`server.js`) is provided for local development.

## Quick Start

You can use this tool in three ways:

1. **Live Demo:** Visit [https://sujal-kadam99.github.io/crypto-hash-generator-explainer/](https://sujal-kadam99.github.io/crypto-hash-generator-explainer/)
2. **Download & Run Locally:** Download the ZIP from the [Releases](https://github.com/Sujal-Kadam99/crypto-hash-generator-explainer/releases) page, unzip it, and double-click `index.html`. No installation and no internet required; hashing works offline; Google Fonts load when online and the page falls back to system fonts when offline.
3. **Local Development (Node >=22):**
   ```bash
   git clone https://github.com/Sujal-Kadam99/crypto-hash-generator-explainer.git
   cd crypto-hash-generator-explainer
   npm start
   ```

### Verify your download

If you downloaded the release ZIP, you can verify its integrity using the provided `SHA256SUMS.txt` file:

**Windows:**
```powershell
certutil -hashfile crypto-hash-generator-explainer-vX.Y.Z.zip SHA256
```
*(Compare the output with the hash inside `SHA256SUMS.txt`)*

**Linux / macOS:**
```bash
sha256sum crypto-hash-generator-explainer-vX.Y.Z.zip
```
*(Compare the output with the hash inside `SHA256SUMS.txt`)*

## Run Tests
To verify the accuracy of the hashing implementations against Node.js's native C++ crypto module:
```bash
npm test
```

## Environment Variables

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `PORT`   | The port for the local static development server | `5173` |

*(Note: Currently, no environment variables are strictly required to run the application).*

## Current Status and Limitations
- The current implementation of the algorithms is fully working and bit-accurate.
- UI features like "Story Mode" and "Avalanche Lab" are operational.
- **Limitations**: The code is not optimized for large files (GBs of data) in the browser, as it processes everything in a single thread memory buffer.

## Roadmap
- **Modular ES migration**: Complete the transition from the monolithic `hash_tool.js` to a cleanly separated, modern ES Module architecture (`js/crypto`, `js/components`).
- Web Worker support for hashing large files without blocking the UI.
- Add HMAC (Hash-Based Message Authentication Code) explainer.

## License
MIT License
