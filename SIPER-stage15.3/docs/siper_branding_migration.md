# Siper public-brand migration

This release changes the public application name from **ELLIOT** to **Siper**.
The official TEKNOFEST project title remains ELLIOT.

Public interfaces:

- GUI title and desktop entry: Siper
- package: `siper-pardus`
- commands: `siper-gui`, `siper-daemon`, `siper-preflight`, `siper-install-check`, `siper-integration-check`
- service alias: `siper.service`

Backward-compatible internal identifiers retained in version 1.0.0:

- Python namespace: `elliot`
- primary unit file: `elliot.service`
- install root: `/opt/elliot`
- socket: `/run/elliot/elliot.sock`
- groups: `elliot`, `elliot-admin`

The legacy `elliot-*` command aliases remain available to avoid invalidating the completed verification evidence and existing installations.
