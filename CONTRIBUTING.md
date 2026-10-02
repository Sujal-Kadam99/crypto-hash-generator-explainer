# Contributing to Crypto Hash Generator & Explainer

First off, thank you for considering contributing to Crypto Hash Generator & Explainer!

## How to Contribute

1. **Fork the Repository**: Create your own fork and branch off `main`.
2. **Write Clean Code**: Crypto Hash Generator & Explainer is 100% vanilla JavaScript. We prefer zero dependencies. Do not add `npm` libraries unless strictly necessary for the build/test pipeline.
3. **Tests**: If you tweak the cryptographic algorithms, ensure you run `npm test` to verify bit-accuracy against the native Node `crypto` library.
4. **Commit Messages**: We use [Conventional Commits](https://www.conventionalcommits.org/). Please format your commit messages appropriately (e.g., `feat: add HMAC support`, `fix: correct bitwise shift in SHA-256`).
5. **Open a Pull Request**: Describe your changes clearly and link any relevant issues.

## Development Workflow
- `npm start` runs the local dev server.
- `npm test` runs the math verification test vectors.
- `npm run lint` lints the codebase.

We welcome all contributions, from fixing typos in the explainer to migrating the architecture to modular ES modules!
