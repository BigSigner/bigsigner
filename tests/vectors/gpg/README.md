# GPG verification fixtures

These are generated test data, not a real release or a real person's key.
Only the public key is retained. The disposable private key was deleted after
the signatures were generated.

- Fingerprint: `FD1FCAF0E2452E9B994941836BF706819116835E`
- UID: `BigSigner GPG Test: Signer <gpg-test@invalid.example>`
- Ed25519 signing key, created with a faked time of 2024-01-01 00:00 UTC and
  a two-year lifetime.
- Signatures were created at 2025-01-01 00:00 UTC. Tests verify at
  2025-06-01 00:00 UTC, independent of the host's current clock.

`release.txt.asc` signs `release.txt`. `SHASUMS.asc` is a detached signature of
`SHASUMS`. `CLEAR.asc` contains the same checksums with a cleartext signature
and has no companion file named `CLEAR`.
