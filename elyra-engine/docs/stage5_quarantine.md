# Stage 5 — Secure quarantine and restoration

## Scope

Stage 5 replaces the provisional quarantine implementation with one canonical,
transaction-oriented manager. It operates only on regular files and is independent of
fanotify/eBPF enforcement. No malware is required for its tests or demonstration.

Canonical implementation:

`src/elyra/response/quarantine_manager.py`

## Quarantine record

Each JSON metadata record uses schema version 1 and includes:

- unique UUID quarantine ID;
- canonical original path;
- SHA-256, byte size and detected file type;
- UTC and numeric timestamp;
- reason, triggered rules, related PID and optional process information;
- original mode, owner/group IDs, device, inode and link count;
- restoration status and, where relevant, restore/delete timestamps and paths.

Metadata is validated when read. Invalid JSON, missing fields, unsupported schema,
invalid IDs, invalid hashes and unsafe metadata paths are reported explicitly rather
than silently skipped.

## Protected storage

Default locations remain:

- `/var/lib/elyra/quarantine/`
- `/var/lib/elyra/metadata/`

The manager requires real directories owned by the service user and forces mode `0700`.
Payloads and metadata use mode `0600`. Metadata writes use a same-directory temporary
file, `fsync`, and atomic replacement.

## Quarantine transaction

1. Canonicalise the parent directory without following the final component.
2. Reject symbolic links, non-regular files and files with multiple hard links.
3. Open with `O_NOFOLLOW`, record device/inode metadata and calculate SHA-256.
4. Compare the hash with the expected analysis hash when supplied.
5. Move the exact opened inode to a private holding name in its original directory.
6. Copy from the open descriptor into a new protected `0600` temporary payload.
7. Verify copied hash, size and source stability.
8. Publish the payload without overwriting another item.
9. Atomically write and validate metadata.
10. Remove the holding file only after the protected payload and metadata exist.

If a recoverable operation fails before commit, ELYRA restores the holding file to the
original path and removes partial payload/metadata files. If the original path has been
reoccupied during rollback, the recovery file is retained and the error reports its
location rather than overwriting the replacement.

## Restoration transaction

- The quarantine ID must be a canonical UUID.
- The metadata and protected payload must both exist and pass validation.
- The payload SHA-256 and size must match the metadata.
- A restore destination must be absolute and its parent must already exist.
- Any existing file, directory or symbolic link at the destination causes a conflict;
  ELYRA never silently overwrites it.
- The output file is created with `O_EXCL | O_NOFOLLOW`, copied and hash-verified.
- SUID and SGID bits are not restored automatically. Ordinary permission bits are
  restored; original ownership is restored only when the daemon is privileged.
- If metadata update fails, the partial restored file is removed only after checking
  its device/inode identity and the previous metadata is restored.

The protected payload remains after restoration so authorised administrators can retain
forensic evidence. Permanent deletion uses a pending rename and metadata rollback, but
IPC authorisation for that action is addressed in later stages.

## TOCTOU and hard-link limitations

The Stage 5 path API substantially mitigates path replacement by using `O_NOFOLLOW`,
device/inode checks and a no-overwrite holding move. It does not claim to eliminate every
race possible in a hostile directory when only a pathname is supplied. Stage 8 should
connect fanotify's kernel-provided file descriptor directly to the quarantine workflow.

Files with multiple hard links are rejected because removing one pathname would not
isolate the same inode through its other aliases.

## Safe demonstration

```bash
PYTHONPATH=src python scripts/demonstrate_quarantine.py \
  --output evidence/quarantine/stage5_quarantine_pardus.json
```

The demonstration uses only temporary harmless byte files. It covers basic
quarantine/restore, identical-content files at different paths, overwrite prevention and
symbolic-link rejection.
