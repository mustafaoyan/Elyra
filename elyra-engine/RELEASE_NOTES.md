# Elyra 1.0.0 Release Notes

ELYRA 1.0.0 is the final controlled TEKNOFEST/Pardus competition release.

## Evidence baseline

- 223 integrated-stage automated tests passed on Pardus in Stage 14.1.
- 254 automated tests pass in the final Stage 15.2 source package baseline.
- Approximately 70% line coverage.
- Real fanotify allow/deny and fail-open behaviour verified.
- Real BCC/eBPF process, exit, file-write, rename and loopback-connect telemetry
  verified.
- Installed fanotify → eBPF → correlation → GUI/API → audit workflow verified.
- Safe terminate → quarantine → restore workflow verified using a private copy
  of `/bin/sleep`.

## Default safety posture

The service starts in `MONITOR_ONLY` mode and does not execute automatic
terminate or quarantine responses. These actions require explicit configuration
and authorisation.

## Not claimed

This release does not claim that high entropy proves malware, that all unknown
malware will be detected, that the audit chain withstands complete privileged
replacement, or that controlled real-malware validation has been completed.

- Elyra public branding added while preserving the verified internal `elyra` namespace for backward compatibility.
- Added `python3-pil.imagetk` to Pardus packaging dependencies so the installed GUI opens on a clean system.
