# Stage 5 factual quarantine audit

The line references in the first table refer to the Stage 4 input repository.

| Issue | Stage 4 file and line | Severity | Effect | Stage 5 correction |
|---|---:|---|---|---|
| Source existence and reads followed symbolic links | `quarantine_manager.py:50, 53, 60, 75` | Critical | A link target could be hashed, copied or removed instead of the intended path | Reject final-component symlinks; open regular files with `O_NOFOLLOW`; compare path and descriptor device/inode |
| Hashing, copying and `os.remove(path)` were separate path operations | `quarantine_manager.py:53–82` | Critical | Path replacement/TOCTOU could remove a different file | Open descriptor, verify stability, move the exact source to a private holding name, then copy from the descriptor |
| Original was removed before metadata was saved | `quarantine_manager.py:82–84` | Critical | Metadata-write failure could cause data loss and an orphan payload | Transactional rollback restores the holding file and removes partial artifacts |
| Metadata was written directly to the final JSON path | `quarantine_manager.py:155–159` | High | Crash or short write could leave corrupt/truncated metadata | `0600` temporary file, full write, `fsync`, atomic replacement and directory sync |
| Restore used `shutil.copy2` without an existence guard | `quarantine_manager.py:93–107` | Critical | An existing legitimate file could be silently overwritten | Absolute target, existing-path rejection, `O_CREAT|O_EXCL|O_NOFOLLOW` |
| Restore hash-failure message claimed rollback but did not remove the output | `quarantine_manager.py:109–110` | High | A partial or corrupt restored file could remain | Identity-checked output rollback and previous-metadata restoration |
| Quarantine IDs were concatenated into paths without validation | `quarantine_manager.py:96, 121, 156, 162` | High | Crafted IDs could attempt path traversal or address unintended files | Require canonical UUIDs before building payload/metadata paths |
| Metadata content had no schema or field validation | `quarantine_manager.py:161–167` | High | Corrupt or manipulated metadata could drive unsafe restoration | Schema version 1 and strict type/hash/path/status validation |
| Corrupt metadata was silently ignored | `quarantine_manager.py:129–135` | High | GUI/daemon could hide missing or damaged records | Strict listing raises explicit errors; optional non-strict mode logs every invalid record |
| Directory modes were applied only when newly created | `quarantine_manager.py:44–45` | Medium | Existing permissive directories could remain exposed | Require real service-owned directories and force `0700`; payload/metadata forced to `0600` |
| Record lacked structured process information and restoration detail | `quarantine_manager.py:24–35` | Medium | Insufficient evidence and recovery traceability | Add process info, original identity/mode/owner, UTC times, restored path/mode and delete status |
| Permanent deletion had no rollback | `quarantine_manager.py:119–125` | High | Metadata and payload state could diverge after an interruption | Pending no-overwrite rename, atomic metadata transition and rollback |
| Multiple hard links were not recognised | No check | High | Removing one path would leave the same inode accessible through aliases | Reject multi-link source files and record source link count |

## Classification

### Confirmed defects repaired

- symbolic-link following;
- restore overwrite;
- non-atomic metadata;
- path traversal through unvalidated IDs;
- removal-before-metadata data-loss window;
- silent metadata corruption handling;
- missing rollback tests and unsafe broad exception swallowing.

### Incomplete features outside Stage 5

- daemon/GUI authorisation for restore and permanent deletion;
- process termination safety and PID reuse protection;
- fanotify descriptor hand-off;
- audit hash-chain and rotation;
- systemd-created directory ownership and packaging.

### Requires Pardus/root verification

- ownership restoration when the daemon runs as root;
- default `/var/lib/elliot` permissions and systemd integration;
- descriptor-based integration with fanotify;
- behaviour under real concurrent enforcement events.
