# Siper Stage 15.3 Branding and Packaging Audit

## Scope

This change renames the public application from **ELLIOT** to **Siper** while preserving **ELLIOT** as the official TEKNOFEST project name.

## Public changes

- GUI window title and sidebar branding changed to Siper.
- Desktop application name changed to Siper.
- Python distribution renamed to `siper-pardus`.
- Public commands added: `siper-gui`, `siper-daemon`, `siper-preflight`, `siper-install-check`, `siper-integration-check`, `siper-submission-check`, and `siper-release-build`.
- `siper.service` added as a systemd alias.
- Debian package renamed to `siper-pardus`.
- Final source, submission, and wheel artifacts use the Siper name.
- README and release documentation now distinguish the Siper application from the ELLIOT project.

## Backward compatibility

The internal Python namespace, primary service unit, protected paths, socket, and groups retain the verified `elliot` identifier. Legacy `elliot-*` console commands remain available. This avoids breaking existing installations and the previously completed Pardus integration evidence.

## Additional packaging correction

`python3-pil.imagetk` was added to the installer and Debian package dependencies. This fixes the clean-Pardus GUI startup failure caused by the missing `PIL.ImageTk` module.

## Verification

- 256 automated tests passed.
- Python source and tests compiled successfully.
- Installer, uninstaller, and Debian builder shell syntax passed.
- Siper release archives and Python wheel were generated.
- All release artifact SHA-256 checks passed.

## Required Pardus follow-up

The renamed package should be installed and retested on Pardus before replacing the previously verified competition submission package. In particular, confirm `siper-gui`, `siper.service`, the installation verifier, the installed integration verifier, and the rebuilt `.deb` package.
