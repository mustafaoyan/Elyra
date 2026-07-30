# Stage 6 IPC evidence

Pardus evidence files:

- `stage6_ipc_pardus.json`
- `stage6_ipc_pardus.png`

The safe demonstration uses a temporary Unix socket owned by the current user. It verifies
framing, protocol versioning, `SO_PEERCRED`, socket mode, malformed input rejection, size
limits, and sensitive-action policy. It does not verify the root-owned production socket.
