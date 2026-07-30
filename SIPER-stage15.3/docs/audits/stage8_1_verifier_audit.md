# Stage 8.1 — fanotify verifier liveness audit

## Confirmed Pardus failure

The Stage 8 root verifier blocked inside Python 3.13 `subprocess.run()` / `os.posix_spawn()` while the child execution was waiting for a `FAN_OPEN_EXEC_PERM` response. Because the parent had not returned from process creation, its timeout logic could not run. The operator had to interrupt the verifier, and no evidence JSON was written.

## Controlled correction

Stage 8.1 changes the verifier only. The fanotify controller, policy, syscall boundary, static analyser, scoring engine, GUI, daemon, and eBPF code are unchanged.

The corrected verifier:

1. starts a dedicated execution broker before fanotify controller threads and launches every test executable in a broker-owned forked child;
2. keeps the verifier parent outside `execve`, so it can continue servicing the controller and enforcing timeouts;
3. uses the parent as an external watchdog;
4. sends `SIGTERM`, then `SIGKILL` if a launcher exceeds its deadline;
5. reaps every launcher to avoid zombie processes;
6. launches concurrent fixtures as independent child processes;
7. writes atomic `IN_PROGRESS` evidence after every completed scenario;
8. preserves partial evidence if the test becomes unavailable or is interrupted;
9. uses only temporary copies of `/bin/true` and a harmless shell script.

## Verification boundary

The generic test suite verifies launcher completion, watchdog termination, and atomic evidence writing. Actual `FAN_OPEN_EXEC_PERM` behaviour still requires the controlled root test on Pardus.
