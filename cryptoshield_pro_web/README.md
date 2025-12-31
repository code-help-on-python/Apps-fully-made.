# CryptoShield Web Decrypt

Static, client-side decrypt page for CryptoShield text tokens.

## Run
Open `index.html` in a browser. No server required.

## Notes
- Format: base64url("CSP1" + 16-byte salt + Fernet token)
- KDF: PBKDF2-HMAC-SHA256, 200,000 iterations
- Fernet: AES-128-CBC + HMAC-SHA256

## License
Proprietary, use-only via the hosted page. See `LICENSE`.
