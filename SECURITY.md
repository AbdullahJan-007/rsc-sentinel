# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.2.x` | Yes |
| `< 0.2.0` | No — please upgrade to `0.2.0` |

## Reporting a Vulnerability

If you discover a security vulnerability in `rsc-sentinel` (such as a guard bypass, path traversal, or command-injection flaw):

1. **Do not open a public GitHub issue.**
2. Report it privately via [GitHub Security Advisories](https://github.com/AbdullahJan-007/rsc-sentinel/security/advisories/new) on this repository.
3. Include:
   - Affected version of `rsc-sentinel` and Node.js / Next.js version
   - Minimal reproduction steps or proof-of-concept test
   - Expected vs. actual security behavior

We aim to acknowledge reports within **48 hours** and release a patched version as soon as a verified fix is ready.

## Security Scope

- **In scope:** `rsc-sentinel/guard` bypasses (size, entry, depth, timeout, option validation), `rsc-sentinel/scanner` path traversal or subprocess handling, and CLI argument handling.
- **Out of scope:** Synchronous CPU-bound JavaScript loops (e.g., unpatched React Flight deserialization DoS). As documented in `README.md`, single-threaded JS timers cannot preempt synchronous loops — always keep React and Next.js updated and enforce reverse-proxy / WAF timeouts.
