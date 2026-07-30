# Stage 15.1 — GUI projection verifier reliability audit

## Confirmed defect

The installed Stage 15 workflow observed the harmless fixture through fanotify,
eBPF and the correlation engine, but the later GUI dashboard refresh sometimes
reported `event_seen: false`. The daemon intentionally retains only the newest
200 events. On a busy Pardus desktop, the fixture record can leave that bounded
window between the correlation poll and the later dashboard refresh.

This was a verifier timing/window defect, not a GUI connection failure: the
failed evidence showed `service_state: CONNECTED`, `policy_mode: MONITOR_ONLY`
and an empty GUI error list.

## Repair

- The integration poll now obtains event and runtime-state records through
  `PardusModel`, the same official API wrapper used by the GUI.
- Exact fixture records returned by that official API are retained in the
  verifier evidence.
- The final GUI projection first checks the live dashboard. If the event has
  already aged out of the bounded daemon buffer, it verifies the presentation
  layer against the exact previously captured official GUI-API records.
- A GUI events-API error still causes failure; no synthetic or fabricated event
  can satisfy the check.
- Evidence explicitly records whether the event came from the live dashboard or
  `CAPTURED_OFFICIAL_GUI_API`.

## Scope

No daemon, fanotify, eBPF, scoring, response, quarantine or enforcement behavior
was changed. Production remains `MONITOR_ONLY` with automatic destructive
responses disabled.
