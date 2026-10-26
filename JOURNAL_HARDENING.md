# Replay journal hardening (2026-10-25)

- Each accepted request ID is appended using a file descriptor and flushed with fsync before the health-check operation is attempted.
- Journal growth is capped at 1 MiB; exhausted capacity rejects further command requests instead of bypassing replay controls.
- Full existing test suite passed: 15/15.

Not yet production ready: no single-instance locking, atomic compaction, power-loss fault-injection validation, session expiration/revocation or authoritative owner approval. Append and fsync do not make concurrent writers safe. Standalone owner gateway still fails closed. Privileged actions remain disabled.
