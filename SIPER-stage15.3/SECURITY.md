# Security Policy

## Reporting a vulnerability

Do not publish exploitable details, credentials, malware samples or sensitive
host logs in a public issue. Report the affected version, component, safe
reproduction steps, expected behaviour, actual behaviour and relevant sanitised
logs to the project maintainers through the competition/team communication
channel.

## Supported release

The final controlled competition release is `1.0.0` for Pardus 25.1 x86_64.
Security fixes should be applied to the current release branch and verified on
the target Pardus kernel before being described as operational.

## Security boundaries

- The daemon is privileged; the GUI is not.
- Sensitive actions require root or explicit `elliot-admin` membership.
- `elliot-admin` must never be assigned automatically.
- Production defaults are `MONITOR_ONLY` and automatic runtime actions disabled.
- No component may automatically download malware.
- Evidence must be sanitised before publication.

## Incident response

1. Stop the service: `sudo systemctl stop elliot.service`.
2. Preserve the current systemd invocation journal and audit files.
3. Record the installed release path and hashes.
4. Do not delete quarantine metadata before recovery is assessed.
5. Reproduce only with harmless fixtures unless a separately authorised
   isolated laboratory procedure is active.
