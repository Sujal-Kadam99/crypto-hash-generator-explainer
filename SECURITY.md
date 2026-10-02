# Security Policy

## Supported Versions

Currently, only the `main` branch of CyberHash is supported with security updates.

## Reporting a Vulnerability

CyberHash is an educational tool and its hashing implementations are **not intended for production cryptographic use**. They are not protected against side-channel attacks or timing attacks.

However, if you discover a traditional vulnerability (e.g., XSS in the explainer UI, prototype pollution, or an issue in the deployment pipeline) that affects the security of users running the tool, please disclose it responsibly.

Please report vulnerabilities by opening a draft Security Advisory on GitHub, or by emailing the maintainer directly. We will attempt to acknowledge and resolve the issue as quickly as possible.

**Do not file a public issue for a security vulnerability.**

## Educational Disclaimer
Once again, MD5 and SHA-1 are cryptographically broken algorithms provided here strictly for historical and educational visualization purposes. Discovering collisions in MD5 or SHA-1 is an expected behavior of these algorithms and is not considered a vulnerability of this repository.
