# MA55 Security Hardening Notes

- Added core/security.py for same-origin CSRF hardening and lightweight in-memory rate limiting.
- Installed hardening centrally via install_security(app).
- Kept worker tick exempt from browser-origin CSRF guard because it uses dedicated worker auth.
- Added tests for cross-origin rejection, same-origin success, and rate-limit triggering via MA_RATE_LIMIT_OVERRIDE.
