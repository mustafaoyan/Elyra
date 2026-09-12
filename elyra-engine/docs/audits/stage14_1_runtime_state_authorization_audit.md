# Stage 14.1 runtime-state authorization audit

| Issue | File and line | Severity | Effect | Proposed fix |
|---|---|---:|---|---|
| `list_runtime_states` was accepted by the protocol and routed by the daemon but absent from the authorization action table | `src/elyra/service/authorization.py` | High | Installed integration checks and GUI runtime-state reads were rejected as an unknown action | Classify it as a read-only action and add cross-layer contract tests |

## Verification classification

- Confirmed defect: verified from the Stage 14 Pardus evidence message `AUTHORIZATION_DENIED: Unknown action: list_runtime_states`.
- Source repair: verified by source inspection.
- Regression protection: verified by automated tests ensuring the protocol and authorization action sets match.
- Installed daemon behaviour: requires Pardus reinstall and rerun of the installed-service integration checker.
