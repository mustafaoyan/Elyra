# Elyra Stage 15.3 Branding and Packaging Audit

## Scope

This change renames the public application from **ELYRA** to **Elyra** while preserving **ELYRA** as the official TEKNOFEST project name.

## Public changes

- GUI window title and sidebar branding changed to Elyra.
- Desktop application name changed to Elyra.
- Python distribution renamed to `elyra-pardus`.
- Public commands added: `elyra-gui`, `elyra-daemon`, `elyra-preflight`, `elyra-install-check`, `elyra-integration-check`, `elyra-submission-check`, and `elyra-release-build`.
- `elyra.service` added as a systemd alias.
- Debian package renamed to `elyra-pardus`.
- Final source, submission, and wheel artifacts use the Elyra name.
- README and release documentation now distinguish the Elyra application from the ELYRA project.

## Backward compatibility

The internal Python namespace, primary service unit, protected paths, socket, and groups retain the verified `elyra` identifier. Legacy `elyra-*` console commands remain available. This avoids breaking existing installations and the previously completed Pardus integration evidence.

## Additional packaging correction

`python3-pil.imagetk` was added to the installer and Debian package dependencies. This fixes the clean-Pardus GUI startup failure caused by the missing `PIL.ImageTk` module.

## Verification

- 256 automated tests passed.
- Python source and tests compiled successfully.
- Installer, uninstaller, and Debian builder shell syntax passed.
- Elyra release archives and Python wheel were generated.
- All release artifact SHA-256 checks passed.

## Required Pardus follow-up

The renamed package should be installed and retested on Pardus before replacing the previously verified competition submission package. In particular, confirm `elyra-gui`, `elyra.service`, the installation verifier, the installed integration verifier, and the rebuilt `.deb` package.
