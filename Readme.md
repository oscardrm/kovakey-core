# TrueVault Core

`vault-core` is the core cryptographic and synchronization engine for TrueVault. It contains zero UI logic and handles:
- AES-GCM encrypted `.vault` blobs and versioned snapshot serialization.
- Local SQLite / SQLCipher persistence and portable in-memory store (`MemStore`).
- Conflict resolution, snapshot merging (Last-writer-wins with deterministic tie-breaks), and side-blob deduplication.
- Password generation, TOTP, and secure memory zeroization.