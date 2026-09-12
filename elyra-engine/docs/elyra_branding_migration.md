# Elyra public-brand migration

This release changes the public application name from **ELYRA** to **Elyra**.
The official TEKNOFEST project title remains ELYRA.

Public interfaces:

- GUI title and desktop entry: Elyra
- package: `elyra-pardus`
- commands: `elyra-gui`, `elyra-daemon`, `elyra-preflight`, `elyra-install-check`, `elyra-integration-check`
- service alias: `elyra.service`

Backward-compatible internal identifiers retained in version 1.0.0:

- Python namespace: `elyra`
- primary unit file: `elyra.service`
- install root: `/opt/elyra`
- socket: `/run/elyra/elyra.sock`
- groups: `elyra`, `elyra-admin`

The legacy `elyra-*` command aliases remain available to avoid invalidating the completed verification evidence and existing installations.
