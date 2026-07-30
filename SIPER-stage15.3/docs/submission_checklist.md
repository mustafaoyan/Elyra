# Final Submission Checklist

## Repository

- [ ] Project name is ELLIOT throughout current files.
- [ ] `README.md`, `LICENSE`, `SECURITY.md`, `CHANGELOG.md` and release notes are present.
- [ ] No `.venv`, cache, password, private key, malware sample or personal absolute path is committed.
- [ ] Source compiles and all tests pass on Pardus.
- [ ] Automatic destructive responses remain disabled in the submitted service.

## Installation and packaging

- [ ] `install.sh` completes on the target Pardus version.
- [ ] `elliot.service` is enabled and active in monitor-only mode.
- [ ] GUI connects after the user logs back in with `elliot` group membership.
- [ ] Final source archive, submission archive, wheel and SHA-256 file are generated.
- [ ] Debian package is built and inspected with `dpkg-deb --info` if it is included in the hand-in.

## Evidence

- [ ] Stage 3–14.1 critical JSON/text evidence is present.
- [ ] Final environment record is generated.
- [ ] Final manifest reports `COMPLETE`.
- [ ] Checksums verify successfully.
- [ ] Screenshots contain no passwords or sensitive personal data.
- [ ] Demonstration video shows architecture, installation, GUI, harmless scan,
      fanotify/eBPF events, audit log and safe restoration.

## Competition submission

- [ ] Public repository URL is correct and accessible to evaluators.
- [ ] Release archive and installation package are attached where required.
- [ ] Report claims match verified evidence and known limitations.
- [ ] No claim says high entropy alone proves malware.
- [ ] No claim says real-malware validation was completed unless separate authorised evidence exists.
