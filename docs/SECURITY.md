# Security Policy

Attack Time Machine is defensive software for forensic recording and reconstruction.

## Non-Goals

This project does not provide exploit code, ransomware code, persistence mechanisms, credential theft, stealth, evasion, or payload execution.

## Sensitive Data

Collectors should not capture file contents, secrets, private keys, passwords, tokens, keystrokes, or packet payloads. Prefer metadata sufficient for incident response:

- process identity
- command metadata where policy allows it
- file paths and content hashes
- network endpoint metadata
- user and host identifiers

## Integrity

Local hash chaining detects later tampering but does not prevent deletion of the entire file. Production deployments should stream records to remote immutable storage.

Use HMAC sealing with a key stored outside the monitored host when possible. A stolen local HMAC key weakens authenticity guarantees.

## Reporting Issues

If you find a security issue, do not publish exploit steps. Open a private report with enough defensive detail to reproduce and fix the problem safely.
