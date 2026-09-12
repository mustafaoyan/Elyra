# Stage 15 Release and Submission Audit

| Issue | Severity | Effect | Stage 15 correction |
|---|---:|---|---|
| README described a development stage rather than a final release | High | Evaluators lacked one authoritative operational guide | Replaced with final architecture, installation, safety, verification and limitations documentation |
| No canonical final evidence inventory | High | Missing or failed evidence could be overlooked | Added strict manifest generation with JSON status validation and SHA-256 inventory |
| No final release archive workflow | High | Submission artifacts were not reproducible | Added deterministic source/submission ZIPs, Python wheel and checksums |
| Debian package path was absent | Medium | Installation package requirement was incomplete | Added target-Pardus Debian builder with embedded Python wheelhouse |
| Real-malware boundary was dispersed | High | Unsafe validation could begin without all controls | Added an explicit laboratory authorisation gate |
| Version remained a development identifier | Medium | Final artifact identity was ambiguous | Set project and package version to 1.0.0 |

The Debian package must be built on the target Pardus/Python architecture. Its
embedded wheelhouse avoids network access during package installation, while
BCC, Clang, libmagic, Tkinter and kernel headers remain declared system
packages.
