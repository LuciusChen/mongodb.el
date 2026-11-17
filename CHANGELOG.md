# Changelog

Notable user-visible changes are recorded here.

## Unreleased

### Added

- `mongodb-command-async`, `mongodb-find-async`, `mongodb-list-collections-async` and `mongodb-list-indexes-async` deliver results or errors through deferred callbacks. Cursor helpers collect subsequent batches and clean up live cursors on failure. `mongodb-busy-p` reports the single connection's request ownership.

## 0.1.1 - 2026-07-15

### Changed

- BSON document boundaries, UTF-8 and booleans are validated strictly, negotiated write limits are enforced, SCRAM work is bounded, and cursor helpers stop at `mongodb-max-cursor-documents` (10,000 by default). Plist connections may use `:auth-database` as an alias for `:auth-source`. Normalized connection metadata is available through `mongodb-connection-host`, `mongodb-connection-port`, and `mongodb-connection-username`.
