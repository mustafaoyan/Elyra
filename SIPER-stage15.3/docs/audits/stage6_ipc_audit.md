# ELLIOT Stage 6 Daemon and IPC Audit

Audit basis: Stage 5 source tree. This stage evaluates only privileged-daemon ownership,
Unix-domain-socket IPC, request validation, peer identity, and authorization boundaries.
It does not claim that fanotify, eBPF, systemd installation, or the GUI workflow is verified.

| Issue | Stage 5 file and line | Severity | Effect | Stage 6 correction |
|---|---:|---|---|---|
| Requests had no protocol version or request identifier | `service/ipc_server.py:79-98`; `gui/model.py:13-28` | High | Client/server schema changes could not be detected or correlated | Added protocol version 1 and mandatory request IDs |
| Buffer growth was unbounded before a newline | `service/ipc_server.py:62-70` | Critical | A local client could exhaust daemon memory | Added a 64 KiB request limit and connection termination |
| Request schema and action parameters were weakly validated | `service/ipc_server.py:80-86` | High | Unknown fields, wrong types, and malformed actions reached privileged code | Added per-action strict schema validation |
| Handler exceptions were returned verbatim | `service/ipc_server.py:96-98` | High | Internal paths and implementation details could leak | Added stable error codes and generic operation failures |
| Stale-path removal used unconditional `unlink` | `service/ipc_server.py:31-33` | Critical | A crafted non-socket path could be deleted by root | Refuse non-sockets and sockets owned by another user |
| Socket mode was `0770` | `service/ipc_server.py:37` | Medium | Execute bits are meaningless for sockets and obscure intended access | Changed to `0660` with dedicated `elliot` group |
| Peer PID was discarded | `service/ipc_server.py:102-106`; `authorization.py:32-34` | Medium | Audit and future PID-sensitive authorization lacked process identity | Requester now includes PID, UID, and GID from `SO_PEERCRED` |
| Sensitive operations relied only on action names, without a versioned request contract | `authorization.py:10-64` | High | Restore, delete, and enforcement changes lacked consistent validation | Strict schemas plus root/`elliot-admin` authorization |
| Manual scans allowed arbitrary daemon-readable paths | `service/daemon.py:158-164` | Critical | An unprivileged GUI peer could use root to inspect unrelated files | Added ownership, regular-file, size, symlink, and allowed-root policy |
| GUI still contained localhost TCP and a world-writable `/tmp` listener | `gui/controller.py:16-34`; `gui/socket_listener.py:10-36` | Critical | Multiple conflicting and insecure IPC mechanisms remained active | Removed TCP and GUI-owned socket; retained only official daemon UDS client |
| Client did not validate response version, ID, size, or framing | `gui/model.py:18-33` | High | Responses could be mismatched, malformed, or oversized | Added canonical `IpcClient` with bounded response validation |

## Remaining limitations

- The production daemon socket requires the `elliot` group, which is created and verified in the installation stage.
- Membership in `elliot-admin` is a coarse Unix-group authorization mechanism. Polkit or a similarly interactive authorization system may be evaluated later, but is not silently claimed here.
- Manual scanning still has a residual path-replacement race between authorization and analysis. The final fanotify integration should pass the kernel-provided file descriptor.
- Actual root-owned `/run/elliot/elliot.sock` startup and systemd confinement require Pardus root verification.
