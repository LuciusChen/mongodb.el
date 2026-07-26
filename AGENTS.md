# mongodb.el Development Guide

This repository is the standalone native MongoDB protocol package used by
Clutch's MongoDB backend.

Read this file before changing code, tests, or docs.  If the implementation and
this guide disagree, fix the drift in the same change or update this guide with
the reason.

## Boundaries

- `mongodb.el` is a protocol package only.  It has no UI, query console,
  result grid, SQL parser, JDBC bridge, MongoDB Shell JavaScript evaluator, or
  caller-specific configuration logic.
- Keep the package single-file before public release.  Do not recreate
  `mongodb-bson.el`, `mongodb-wire.el`, `mongodb-params.el`, `mongodb-auth.el`,
  or similar split modules unless there is a concrete, reviewed reason that
  reduces total complexity.
- External consumers load `(require 'mongodb)` and use public `mongodb-`
  symbols only.
- Clutch owns MQL helper parsing, query-buffer mode, completion, result-grid
  rendering, connection prompts, auth-source/pass resolution, SSH/TRAMP
  forwarding, and MongoDB SQL Interface routing.
- Ordinary MongoDB support is native wire protocol.  MongoDB SQL Interface is a
  separate JDBC surface owned by caller applications and must not influence this
  package's API, naming, tests, or dependencies.

## Supported Scope

Keep support focused on the currently useful native surface:

- BSON encode/decode and BSON wrapper values
- direct TCP/TLS, `mongodb://`, plist params
- SCRAM-SHA-256 and SCRAM-SHA-1
- OP_MSG command execution
- cursor `getMore` / `killCursors`
- helpers for find, aggregate, count, distinct, insert, update, delete,
  collection/index metadata, create/drop collection/index, explain, and drop
  database

Do not add driver-spec areas by default:

- `mongodb+srv`, seed-list discovery, SDAM, pooling, sessions, transactions,
  retryable reads/writes, compression, load-balanced mode
- X.509, PLAIN, AWS, OIDC, client-side encryption, change streams, bulkWrite
- shell, SQL, JDBC, ODBC, BI Connector, GUI/query-console behavior

If one of these becomes necessary, write down why it is necessary now, what
caller needs it, and what tests prove it.

## Design Discipline

- Find the root cause before changing behavior.  Do not add fallbacks that hide
  protocol failures.
- Delete, do not deprecate, before public release.  Avoid compatibility shims,
  re-exports, and renamed wrappers.
- Reduce code by improving ownership and invariants, not by moving code around.
- Add abstractions only when they remove real duplication or make callers
  simpler.
- Keep public helpers thin and predictable.  Internal helpers use `mongodb--`;
  public API uses `mongodb-`.
- Use `mongodb-error` for protocol/client failures.
- Return protocol data, not caller UI data.
- Do not call private APIs from other packages, such as `clutch--*`,
  `mysql--*`, `pg--*`, or `tramp-rpc--*`.

## Tests

- Tests must fail when the code is wrong.  Do not keep tests that only assert
  implementation trivia.
- Match test weight to the supported scope.  Avoid upstream driver spec-suite
  creep for unsupported features.
- For protocol changes, run unit tests, byte-compile, and a live MongoDB smoke
  test.
- When a public `mongodb-` API used by Clutch changes, update the Clutch adapter
  in the same overall change and rerun Clutch's MongoDB-focused tests.

## Pre-Commit Checklist

Run the steps that are possible in the current environment:

```bash
git diff HEAD

emacs -Q --batch --eval '(setq load-prefer-newer t)' \
  -L . -l ert -l test/mongodb-test.el \
  --eval '(ert-run-tests-batch-and-exit)'

emacs -Q --batch -L . -f batch-byte-compile mongodb.el test/mongodb-test.el
rm -f *.elc test/*.elc

rg -n -P "(?<![A-Za-z0-9-])(clutch|mysql|pg|tramp-rpc)--[A-Za-z0-9-]+" \
  mongodb.el test/*.el
```

If the sibling Clutch checkout is present:

```bash
rg -n -P "require 'mongodb-(wire|bson|params|auth)|(?<![A-Za-z0-9-])mongodb--[A-Za-z0-9-]+" \
  ../clutch/clutch*.el ../clutch/test/*.el
```

This must return no matches.  Clutch must use `(require 'mongodb)` and public
`mongodb-` APIs only.
