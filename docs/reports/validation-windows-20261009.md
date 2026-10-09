# VANGUARD validation report

Generated 2026-10-09T20:28:46Z on windows/amd64 (go1.27.0).

## Go tests

498 passed, 0 failed, 10 skipped (test events incl. subtests).

Skipped tests (**not** passes): 10

## Lab

suite status comes from lab/run-all.sh: only assertions the scripts printed count; blocked/skipped suites did not run

## Not run (unverified)

- **Linux-only tests** — this run was on Windows (10 hostsec tests skip)
- **race detector** — no CGO toolchain on this machine
- **real ufw verification** — no disposable Linux firewall

## Caveats

- Counts are test events found in the supplied files; nothing is extrapolated.
- Passing synthetic tests/lab scenarios show behaviour on isolated fixtures, not real-world detection efficacy, false-negative or false-positive rates.
- A report generated on one OS says nothing about another: Linux-specific behaviour is only verified by a Linux run.
