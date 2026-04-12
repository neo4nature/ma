# MA57 — Docs Sync + Versioning Notes

What changed:
- refreshed README to match the actual current snapshot
- documented current blueprint/service split and security hardening
- documented that firmware mode defaults to SERIAL (PTY) unless SOCKET is requested
- added BUILD_INFO.json as the canonical snapshot marker inside the bundle
- added docs/MA57_STATUS.md

Why:
- reduce drift between bundle name, internal directory name, and current behavior
- give a single in-bundle source of truth for the snapshot identity
