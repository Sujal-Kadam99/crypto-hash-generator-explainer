# CyberHash

**An educational, real-time cryptographic hash generator and visual explainer.**

![CyberHash Screenshot Placeholder](placeholder-screenshot.png)

## Overview

CyberHash is a 100% offline, local, bit-accurate cryptographic hash engine and visual explainer. It computes MD5, SHA-1, SHA-256, and SHA-512 hashes instantly using pure JavaScript, without any external dependencies. It's designed to help developers and students intuitively understand how hashing functions, the avalanche effect, and the block-round math work under the hood.

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
CyberHash uses a monolithic, zero-dependency architecture for the main application (`hash_tool.js`), which contains bitwise implementations of all cryptographic algorithms, alongside DOM manipulation logic to render the visual explainer tabs dynamically. It runs fully offline in the browser. A tiny Node.js static server (`server.js`) is provided for local development.

## Prerequisites
- **Node.js** (v20.0.0 or higher recommended) for local development server and testing.
- A modern web browser.

## Install and Run

1. Clone the repository:
   ```bash
   git clone https://github.com/sujal-kadam99/cyberhash.git
   cd cyberhash
   ```
2. Start the local server:
   ```bash
   npm start
   ```
3. Open `http://localhost:5173/` in your browser.

*Note: You can also simply open `index.html` directly in your browser without the server, as it's fully self-contained!*

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
