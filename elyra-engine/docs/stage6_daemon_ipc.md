# Stage 6 — Privileged Daemon and Unix-Domain-Socket IPC

## Official transport

ELYRA uses one local transport: `/run/elyra/elyra.sock` with newline-delimited UTF-8
JSON. TCP and the former GUI-owned `/tmp` socket are removed.

Production ownership policy:

- daemon: root;
- socket group: `elyra`;
- runtime directory: `0750`;
- socket: `0660`;
- sensitive operations: root or `elyra-admin`;
- peer identity: Linux `SO_PEERCRED` PID/UID/GID.

## Protocol version 1

Request:

```json
{"version":1,"request_id":"...","action":"get_status","params":{}}
```

Success response:

```json
{"version":1,"request_id":"...","ok":true,"result":{}}
```

Error response:

```json
{"version":1,"request_id":"...","ok":false,"error":{"code":"...","message":"..."}}
```

Requests are limited to 64 KiB and responses to 2 MiB. Every action has an explicit
parameter schema. Unknown actions, fields, types, and versions are rejected before the
daemon handler runs.

## Manual scan policy

A non-root peer may request a scan only for a regular, non-symlink file that it owns under
its home, `/tmp`, `/var/tmp`, `/run/user/<uid>`, or its removable-media roots. The default
manual scan size limit is 512 MiB. Root and `elyra-admin` may scan other regular files.

## Degraded and unverified areas

The temporary Stage 6 demonstration does not start fanotify, eBPF, systemd, or the GUI.
Production group creation, root socket ownership, and systemd confinement remain pending
Pardus root verification. The GUI's functional data binding is Stage 7.
