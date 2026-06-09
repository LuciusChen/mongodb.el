# mongodb.el Development Guide

Elisp best practices for the native MongoDB protocol client.  This repository
is the standalone protocol package used by Clutch's MongoDB backend.

Treat this file as the development contract for future `mongodb.el` work.  When
code, tests, or docs drift from these rules, fix the drift in the same change
or update this guide with the new boundary and the reason for it.

Before changing this repository, read this file and apply it to the current
change.  Before changing the sibling Clutch adapter, read Clutch's own
`AGENTS.md` as well.  When the two guides disagree, stop and clarify the package
boundary in the guides before adding code.

## Core Principles

- **Question every abstraction**: Add layers, files, or indirection only when
  they solve a current problem.  Prefer simple code and clear ownership over
  speculative structure.
- **Refactor for net value**: A refactor must improve architecture,
  implementation simplicity, code size, robustness, extensibility, or test
  value.  Moving code or renaming layers is not enough.
- **Make abstractions pay for themselves**: A refactor should remove
  duplication, centralize a rule, or make callers simpler.
- **Root out helper stacking**: Treat piles of tiny helpers, one-use wrappers,
  accessor layers, and pass-through functions as structural debt.  Inline
  trivial one-use helpers, collapse wrapper ladders, or move the workflow into
  the module that owns it.
- **Reduce code by improving the model**: Prefer simpler state, data flow,
  control flow, and ownership.  Do not treat file extraction as the primary
  route to code-size reduction.
- **Prefer lightweight Elisp shapes**: Use `let*`, `pcase-let`, alists/plists,
  small helpers, or table-driven mappings for short-lived context.  Reserve
  `cl-defstruct` for stable data that crosses protocol or lifecycle boundaries.
- **Delete, don't deprecate**: Remove unused code entirely.  No
  backward-compatibility shims, re-exports, or "removed" comments before a
  public release.
- **Converge interfaces**: Prefer one clear public API and one consistent
  behavior model over overlapping commands, alternate driver surfaces, or
  branchy caller-specific behavior.
- **Spec scope beats line-count anxiety**: MongoDB protocol support naturally
  spans BSON, wire messages, URI normalization, auth, topology, sessions,
  retries, transactions, compression, and pooling.  Reduce code by improving
  ownership and invariants, not by dropping required driver behavior.

## Diagnosis and Change Discipline

- **Find the root cause before changing behavior**: Do not patch protocol,
  timeout, parsing, or lifecycle behavior until you can name the failing layer.
- **One failed fix narrows the hypothesis**: If the first attempted fix does
  not hold, gather evidence instead of stacking speculative patches.
- **Two failed fixes stop the patching loop**: After two failed fixes on the
  same issue, stop changing behavior and switch to diagnosis only.
- **Fix the right layer**: BSON belongs in the BSON module, wire framing in the
  message module, connection URI parsing in connection parameters, auth in auth,
  and caller UI syntax in the caller application.
- **Stabilize protocol changes before coding**: For changes that alter public
  APIs, handshake behavior, server selection, auth, transactions, or pooling,
  write a short design note or doc update first.
- **Keep experiments narrow**: Start new protocol directions with the smallest
  slice that proves the behavior against unit tests or a live server.
- **Audit broadly for refactors**: For project-wide cleanup, review `*.el`,
  tests, docs, and the Clutch adapter before choosing changes.
- **Flag compensating code as design debt**: When you find code that compensates
  in the wrong layer, record it in docs or a design note instead of hiding it
  behind another fallback.

## Error Handling and Testing Discipline

- **Errors must surface, not hide**: Do not add fallback/default returns that
  silently swallow protocol failures.
- **Catch at the boundary, nowhere else**: Only public API boundaries should
  translate low-level failures into `mongodb-error`.  Internal logic should not
  `condition-case` around bugs.
- **Robustness is not defensive programming**: Prefer clear ownership, fewer
  states and branches, explicit error boundaries, and verifiable invariants.
- **Error messages should describe the current problem**: Prefer concrete
  messages such as "Unsupported MongoDB wire version" or "No writable server"
  over command-style wording.
- **Tests must fail when the code is wrong**: If deleting or breaking the
  function under test does not turn the test red, the test is not useful.
- **Test the real dispatch path for protocol bugs**: For command routing,
  retries, sessions, transactions, compression, and auth, include tests that
  drive the same public path callers use where practical.
- **Match test weight to change size**: Use the smallest test that proves the
  intended behavior.  Do not add heavy tests for comment-only or mechanical
  changes.
- **Treat tests as architecture budget**: Keep tests that prove public
  workflows, real invariants, and meaningful edge cases.  Remove or simplify
  tests that only lock implementation details.
- **No hard-coded expectations**: Use diverse inputs, boundary cases, and
  multiple data sets so a hard-coded return cannot satisfy all assertions.
- **Red before green for real bug fixes**: For a correctness issue, first write
  or identify a failing test, confirm it fails, then fix the code.

## Architecture and Implementation

- **Protocol package only**: `mongodb.el` has no UI, query console, result grid,
  SQL Interface routing, or MongoDB Shell JavaScript evaluator.  Those belong
  in caller applications such as Clutch.
- **Native client, not shell or JDBC**: The ordinary path is
  `mongodb.el -> mongod/mongos` through native MongoDB commands.  Do not route the
  document surface through `mongosh`, JavaScript subprocesses, JDBC, or the
  MongoDB SQL Interface.
- **SQL translation is a companion concern**: Non-JDBC SQL support, if pursued,
  must live in a separate package or caller application that parses SQL and
  emits MongoDB commands or aggregation pipelines through public `mongodb-` APIs.
  Do not add a SQL parser, relational planner, BI Connector / `mongosqld`
  client, or SQL query console to this protocol package.
- **External dependency boundaries stay explicit**: Do not add dependencies on
  Clutch, JDBC agents, Java drivers, `mongosh`, or GUI/query-console packages.
  Optional integrations belong in caller applications.
- **No external private APIs**: Do not call another package's double-dash
  symbols such as `clutch--*`, `mysql--*`, `pg--*`, or `tramp-rpc--*`.  If this
  package needs behavior that only exists behind a private helper, add or
  request a public API in that package.
- **Public entry point stays `mongodb.el`**: External consumers load
  `(require 'mongodb)`.  Split files are implementation modules assembled by the
  entry file.
- **Split by stable protocol boundaries**: Prefer complete responsibilities
  such as BSON codecs, wire message framing, URI/connection parameters, auth,
  topology/server selection, commands/cursors, transactions, and pooling.  Do
  not split into vague `common`, `utils`, or `helpers` modules.
- **Stop splitting before glue takes over**: If an extraction mostly adds
  declarations, pass-through wrappers, or cross-file hopping, keep ownership
  direct or choose a better boundary.
- **Use declarations to keep modules honest**: When a split module depends on
  shared globals or functions defined elsewhere, add explicit `defvar` /
  `declare-function` forms so byte-compilation stays clean.
- **Do not use declarations as boundary patches**: A new declaration to a
  higher-level module is a design smell.  Move the interface to the owner module
  or expose a real public API.
- **Favor incremental modularization**: Move the smallest coherent slice first,
  then reload, byte-compile, and run focused tests before the next extraction.
- **No behavioral side effects on load**: Loading files must not open sockets,
  start monitors, alter editing behavior, or mutate server state.
- **State placement**: Use connection/pool/session structs for protocol state,
  plain `defvar` for shared constants or caches, `defvar-local` only for
  buffer state in tests or caller-facing utilities, and `defcustom` for user
  options.
- **Public naming**: `mongodb-` for supported public API.  No double dash for
  public API.
- **Private naming**: `mongodb--` inside this package.  Do not ask callers to use
  private symbols; promote a real public API when external code needs one.
  Clutch and other callers must use only public `mongodb-` symbols.
- **Predicates**: Multi-word predicate names end in `-p`.
- **Unused args**: Prefix with `_`.
- **Prefer flat control flow**: Avoid deep `let` -> `if` -> `let` nesting.  Use
  `if-let*`, `when-let*`, `pcase`, and `pcase-let`.
- **Prefer destructuring over repeated accessors**: Use `pcase-let` to
  destructure lists and plists instead of repeated `nth` or `plist-get` calls.
- **Prefer `cl-loop` for non-trivial accumulation**: Use it instead of
  `dolist` plus manual accumulators or over-clever folds.
- **Use the right error type**: `mongodb-error` for protocol/client failures,
  `user-error` for caller-caused interactive problems, and `error` for
  programmer bugs.
- **Do not wrap stdlib errors without semantics**: Use built-in errors directly
  unless a wrapper adds behavior that the docstring names.
- **Prefer idiomatic primitives**: Use `vconcat` to build vectors from lists,
  not `apply #'vector`.  Predicates returning non-nil need no `(not (null ...))`
  wrapper.
- **Function design**: Keep functions short, separate pure computation from
  transport mutation, and keep public helpers thin.
- **Return protocol data, not caller UI data**: Public APIs may return BSON
  wrapper values, documents, lists, cursors, sessions, command replies, and
  connection state.  They must not return Clutch result-grid structs,
  query-console parse trees, transient menu state, or SQL Interface artifacts.
- **Dead code does not stay around**: If protocol support moves, is replaced, or
  becomes unreachable, remove the old path rather than leaving compatibility
  stubs, renamed wrappers, or "removed" comments.

## Caller Boundaries

- Clutch owns MongoDB Shell/MQL helper parsing, query console mode, completion,
  result-grid rendering, connection prompts, auth-source/pass resolution, and
  SQL Interface surface selection.
- `mongodb.el` owns BSON values, URI/params normalization, sockets, TLS, wire
  compression, OP_MSG/legacy response framing, server selection, auth, sessions,
  transactions, cursors, command helpers, and pooling.
- Ordinary MongoDB support is native wire protocol.  MongoDB SQL Interface is a
  separate JDBC surface owned by caller applications; it must not influence this
  package's protocol API, naming, tests, or dependencies.
- When Clutch needs new protocol behavior, add it to `mongodb.el` as a public
  `mongodb-` API and update Clutch to call that API.  Do not work around missing
  protocol APIs by calling `mongodb--*` from Clutch.
- Caller applications should be able to pass structured connection plists or
  `mongodb://` / `mongodb+srv://` URLs directly to `mongodb-connect`.  If a caller
  needs effective connection facts such as selected database, topology, server
  address, or negotiated options, expose them through public `mongodb-` accessors
  instead of making the caller parse MongoDB URLs or duplicate parameter
  normalization.
- Do not migrate Clutch's MQL helper reader, shell-like query snippets,
  completion tables, result-grid shaping, auth-source/pass-entry lookup, SSH /
  TRAMP forwarding, or SQL Interface routing into this repository.  They are
  caller UX and integration code, not MongoDB protocol implementation.
- After changing a public `mongodb-` API used by Clutch, update the Clutch adapter
  in the same overall change and rerun Clutch's MongoDB-focused tests before
  considering the protocol change complete.

## Clutch Residue Audit

Keep the split between `mongodb.el` and the sibling Clutch checkout explicit.
Clutch should retain only caller-facing MongoDB code:

- `clutch-mongodb.el` may adapt public `mongodb-` APIs to Clutch's generic
  database contract, including MQL helper parsing, result-grid shaping,
  collection metadata, and document-surface query execution.
- The Clutch MongoDB adapter may hold the public `mongodb-conn` object as an
  opaque client handle.  It should name that handle as `client` or connection
  state, not as `wire`, `protocol`, socket, pool, or topology state.
- `clutch-mongodb-mode` may own query-buffer syntax, highlighting, and
  completion for the supported helper surface.
- `clutch-db-jdbc.el` may keep MongoDB SQL Interface JDBC routing for
  `:backend mongodb :surface sql-interface`, including the internal JDBC driver
  key `mongodb`.
- Clutch docs and tests may mention MongoDB SQL Interface as a product name and
  may keep `:mongodb-surface-sql-live` test tags.

The following must not drift back into Clutch:

- direct requires of `mongodb-wire`, `mongodb-bson`, `mongodb-params`, or
  `mongodb-auth`;
- calls to private `mongodb--*` symbols;
- BSON codec, wire message framing, URI/SRV parsing, auth, sessions,
  transactions, server selection, cursor, retry, compression, or pooling
  implementation;
- protocol capability prose in Clutch user docs that duplicates details such as
  `OP_MSG`, compression negotiation, SASL/SCRAM behavior, `serviceId`, `lsid`,
  `endSessions`, or server-selection rules;
- MongoDB URI synthesis, URL database extraction, or connection-option
  interpretation beyond treating `:url` as an opaque saved connection value;
- any dependency on `mongosh`, JavaScript evaluation, or shell subprocesses for
  the native document surface;
- a public `mongodb-sql` / `mongodb_sql` backend, feature, driver, manual
  chooser entry, or saved-connection example.

User-facing Clutch configuration remains one backend: `:backend mongodb`.
MongoDB SQL Interface is an optional surface of that backend:
`:backend mongodb :surface sql-interface`.  If Clutch needs protocol behavior
that is not available publicly, add a `mongodb-` API here first instead of using a
private helper from Clutch.

## Protocol Boundaries

- **BSON is not MQL**: BSON encode/decode accepts Elisp values and explicit BSON
  wrapper structs.  MQL text parsing is not part of this repository.
- **Wire protocol is not JDBC**: This package talks to `mongod` / `mongos`
  through MongoDB wire messages.  SQL Interface JDBC support belongs outside
  this package.
- **Modern protocol first**: Use `OP_MSG` as the normal command path.  Legacy
  opcodes may exist only for handshake compatibility where the server requires
  them.
- **Spec-driven behavior**: URI parsing, server selection, retry labels,
  sessions, transactions, auth, compression, and pooling should follow MongoDB
  driver specifications where feasible.  When deliberately incomplete, document
  the boundary.
- **Auth stays native**: SCRAM, X.509, PLAIN, MONGODB-AWS, and OIDC
  implementations must send native MongoDB SASL/command payloads, not shell or
  JDBC requests.
- **Timeouts must be explicit**: Socket, connect, server selection, and command
  timeouts should be visible in params and tests.  Avoid hidden indefinite waits.

## Version Baseline

- `mongodb.el` targets **Emacs 29.1+**.
- Do not silently raise the baseline.  If a change requires a higher Emacs
  version, update `README.org`, package metadata, and a design note explaining
  why.

## Documentation and Release Records

- Any change to public functions, params, defaults, supported wire behavior, or
  live-test expectations must update `README.org` or `docs/` in the same change.
- If code and docs diverge, treat code as source of truth and fix docs
  immediately.
- Optimize documentation for the rendered reader, not source-width aesthetics.
  Do not rewrap unchanged prose only to fit a column.
- Write a design note when choosing between non-obvious protocol approaches,
  integrating an optional dependency, abandoning a path, or deliberately
  deferring a known MongoDB driver-spec area.
- Design notes must explain **why**, not restate the code.
- Design notes are historical decision records, not current product
  documentation.  Do not rewrite old notes just to match current behavior; add a
  newer note or a short supersession pointer when a later design replaces an
  older one.
- Public behavior, test expectations, and support boundaries should be kept in
  `README.org` and `docs/`.  Caller-specific documentation should stay in the
  caller repository and link here for protocol details.

## Quality and Release Checks

- Byte-compile distributable `mongodb*.el` files with zero warnings after code
  changes.
- Run checkdoc on distributable `mongodb*.el` files and package-lint on
  `mongodb.el` before release.
- Run live MongoDB tests for changes that touch sockets, TLS, URI/SRV parsing,
  auth, command execution, cursors, sessions, retry behavior, transactions,
  compression, server selection, or pooling.
- Exported/public API changes must include regression tests and documentation.
- Optional external programs such as `zstd` must be detected explicitly and
  documented; do not silently change protocol support based on PATH accidents.

## MELPA Compatibility Checklist

### Emacs 29.1 baseline

- Do not use Emacs 30+ APIs without a version guard or compatibility shim.
- When in doubt, check `M-x find-function` to verify when a symbol was
  introduced.

### File headers

- First line: `;;; file.el --- Short description -*- lexical-binding: t; -*-`
  - Description must not contain "for Emacs" or the package name.
  - Keep the description under 60 characters.
- `mongodb.el` is the package entry file.  It is the only file that should carry
  package metadata such as `;; Package-Requires:`, `;; URL:`, `;; Version:`,
  and `;; Author:`.
- `;; Package-Requires:` in `mongodb.el` must list all direct dependencies with
  minimum versions, including the declared Emacs baseline.
- Split implementation files must not carry `;; Package-Requires:` headers, but
  they must carry formal license metadata, preferably
  `;; SPDX-License-Identifier:`.
- Keep the MELPA checklist attribution in the main package file when AI tools
  materially assist the package:
  `;; Assisted-by: OpenAI Codex:gpt-5.5`
- Last line: `;;; file.el ends here`

### Naming

- Follow the public/private naming rules above.  Internal structs, maps,
  constants, and helpers use `mongodb--`.
- User-facing commands and public helpers use `mongodb-`.
- Every `defcustom` must specify `:type`.

### Autoloads

- Add `;;;###autoload` only to user-facing commands users call via `M-x`.
- Do not autoload internal helpers, variables, or private functions.

### checkdoc

- Every public `defun`, `defmacro`, `defcustom`, and `defvar` must have a
  docstring.
- Docstring first line must be a complete sentence ending with a period.
- Argument names in docstrings should be UPPERCASED.
- Run checkdoc across distributable `mongodb*.el` files.

### Common pitfalls

- `cl-lib` functions require `(require 'cl-lib)`; do not rely on transitive
  loading.
- Avoid `eval-when-compile` for runtime-needed dependencies.
- Compatibility shims must stay in the `mongodb--` namespace.
- Avoid `with-eval-after-load` in package code unless the form registers an
  optional integration at a clear package boundary.

## Pre-Commit Checklist (Mandatory)

Every commit must pass all of these steps unless a step is impossible in the
current environment.  When a step is skipped, record the reason.

### 1. Read the full diff

```bash
git diff HEAD
```

Read every changed line before committing.

### 2. Run unit tests

```bash
emacs -Q --batch -L . -l ert -l test/mongodb-test.el \
  --eval '(ert-run-tests-batch-and-exit "mongodb-test-.*")'
```

### 3. Check external private API boundaries

```bash
rg -n -P "(?<![A-Za-z0-9-])(clutch|mysql|pg|tramp-rpc)--[A-Za-z0-9-]+" \
  mongodb*.el test/*.el
```

This command should return no matches.  Internal `mongodb--*` symbols are allowed
inside this repository.

If the sibling Clutch checkout is present, also verify that Clutch still depends
only on public `mongodb-` APIs:

```bash
rg -n -P "(?<![A-Za-z0-9-])(mysql|mongodb|nerd-icons|tramp-rpc)--[A-Za-z0-9-]+" \
  ../clutch/clutch*.el ../clutch/test/*.el
```

That command should also return no matches.

### 4. Check protocol-layer residue in Clutch

If the sibling Clutch checkout is present, ensure Clutch has not started
depending on split implementation files or shell executables:

```bash
rg -n -P "require 'mongodb-(wire|bson|params|auth)|(?<![A-Za-z0-9-])mongodb--[A-Za-z0-9-]+|mongosh" \
  ../clutch/clutch*.el ../clutch/test/*.el
```

This command should return no matches.  Clutch must use `(require 'mongodb)` and
public `mongodb-` APIs only.

Also check that Clutch has not copied MongoDB URI parsing or synthesis back into
its native adapter:

```bash
rg -n "clutch-mongodb--.*(uri|url)|url-hexify-string|url-unhex-string" \
  ../clutch/clutch-mongodb.el ../clutch/test/*.el
```

This command should return no matches.  `:url` may be an opaque saved
connection parameter in Clutch; URL interpretation belongs in `mongodb.el`.

Also check that Clutch's native adapter does not expose protocol-layer naming as
its own state:

```bash
rg -n "conn-wire|:wire|OP_MSG|wire protocol|MongoDB wire" \
  ../clutch/clutch-mongodb.el
```

This command should return no matches.  Clutch may hold a public `mongodb-conn`
as an opaque client handle; wire/protocol terminology belongs here.

Also check that Clutch user docs do not duplicate detailed MongoDB protocol
capability prose:

```bash
rg -n "OP_MSG|wire compression|BSON wrappers|SASLprep|server selection|load-balanced|serviceId|lsid|endSessions|speculative SCRAM" \
  ../clutch/README.org ../clutch/docs ../clutch/PRD.md
```

This command should return no matches.  Clutch docs may say that ordinary
MongoDB uses the external `mongodb.el` native client, then link here for protocol
details.

### 5. Check MongoDB surface naming in Clutch

If the sibling Clutch checkout is present, ensure MongoDB SQL Interface has not
reappeared as a second backend or driver:

```bash
rg -n "mongodb[-_]sql(|[-_]interface)" \
  ../clutch/clutch*.el ../clutch/test/*.el ../clutch/README.org ../clutch/docs
```

This command should return no matches.

Also verify that user-facing Clutch documentation does not recommend
`:driver mongodb` configuration:

```bash
rg -n ":driver +'?mongodb|:driver +mongodb" \
  ../clutch/README.org ../clutch/docs ../clutch/PRD.md
```

This command should return no matches.  `:driver 'mongodb` may still appear as
internal JDBC connection state or in rejection tests, but not in public
configuration examples.

### 6. Run live tests when protocol behavior changes

Use a real local or remote MongoDB deployment for changes touching transport,
URI parsing, auth, sessions, transactions, server selection, retry behavior,
compression, or command execution.  A local `mongod` is enough for ordinary
document-surface protocol tests; SQL Interface JDBC tests are outside this
repository.

When the sibling Clutch checkout is present and a public `mongodb-` API used by
Clutch changes, rerun Clutch's MongoDB live adapter tests too.

### 7. Byte-compile with zero warnings

```bash
emacs -Q --batch -L . -f batch-byte-compile mongodb*.el test/mongodb-test.el
```

Remove generated `*.elc` files after byte-compilation in a source checkout
unless they are intentionally committed artifacts.

### 8. Run package checks before release

Run package-lint on `mongodb.el`, and run checkdoc across distributable
`mongodb*.el` files.  Do not move package metadata into split files to satisfy
per-file lint.

### 9. Update tests when behavior changes

When behavior changes intentionally, update existing relevant tests first.  Add
a new failing test only when the current suite does not already prove the
regression or changed behavior.
