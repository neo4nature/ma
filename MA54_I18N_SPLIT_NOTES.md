# MA54 — i18n split notes

What changed:
- moved inline i18n dictionaries and helpers out of app.py into core/i18n.py
- kept runtime behavior the same by installing context processor and before_request hook via install_i18n(...)
- added regression tests for language loading and feed render

Why this matters:
- reduces app.py size without changing route behavior
- prepares the codebase for future extraction of UI concerns from the monolith
