# Changelog

Notable user-visible changes are recorded here.

## Unreleased

## 0.1.1 - 2026-07-15

### Changed

- BSON document boundaries, UTF-8 and booleans are validated strictly, negotiated write limits are enforced, SCRAM work is bounded, and cursor helpers stop at `mongodb-max-cursor-documents` (10,000 by default). Plist connections may use `:auth-database` as an alias for `:auth-source`. Normalized connection metadata is available through `mongodb-connection-host`, `mongodb-connection-port`, and `mongodb-connection-username`.
