# Stage 12 — Secure, Structured, Tamper-Evident Audit Logging

Stage 12 replaces the minimal append-only logger with one canonical audit subsystem.

## Record format

Each new JSONL record contains:

- schema version and unique record ID;
- monotonically increasing sequence number;
- Unix and UTC timestamps;
- source and subject;
- recursively JSON-safe structured payload;
- previous record hash;
- current SHA-256 record hash.

The active directory defaults to mode `0750`, the audit file to `0640`, and the
inter-process lock file to `0600`. Symbolic-link log paths are rejected.

## Integrity and startup behaviour

The complete retained chain is verified when `AuditLogger` starts. Corruption
uses one of two explicit policies:

- `raise` (default): refuse startup with `AuditIntegrityError`;
- `quarantine`: atomically preserve the untrusted segments under a protected
  `corrupt/` directory and begin a new chain with a recovery record.

A final partial JSONL record caused by an interrupted append may be preserved as
a binary recovery artifact and truncated from the active file. Records before
the partial fragment must still pass full hash verification.

## Rotation and retention

Rotation uses atomic rename and directory `fsync`. The hash chain continues
across rotated files. If retention removes old segments, verification is marked
`RETAINED_WINDOW` rather than incorrectly claiming genesis-level coverage.

## Crash and concurrency handling

- records are encoded before opening the log;
- writes use `O_APPEND`, `O_NOFOLLOW` where available, a process lock, and an
  in-process lock;
- the file and containing directory are synchronised with `fsync`;
- multiple logger instances refresh the last retained hash while holding the
  inter-process lock.

## Threat-model limitation

The SHA-256 chain is tamper-evident for the retained files: changing, deleting,
reordering, or inserting a retained record is detectable. It does **not** prevent
a privileged attacker from replacing the complete log set and recomputing every
hash. Stronger guarantees require an external append-only or remotely anchored
trust mechanism, which is outside Stage 12.
