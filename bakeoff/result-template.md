# Bake-off result: `<candidate>/<profile>`

## Identity

| Field | Value |
| --- | --- |
| Candidate | |
| Profile (`default` or `hardened`) | |
| Version, Git SHA, package and image digests | |
| Plugin, channel, skill, and provider revisions | |
| Disposable VM image and kernel | |
| Runtime and dependency versions | |
| UTC test interval | |
| Tester | |
| Configuration/evidence bundle SHA-256 | |

## Topology and residual authority

Describe process, UID, container/VM, socket, mount, credential, and network
boundaries. State which component can read each token, database, workspace, and
runtime socket. Distinguish observed facts from documentation-derived claims.

## Results

Use only `PASS`, `FAIL`, `NOT_SUPPORTED`, `NOT_OBSERVABLE`, or `BLOCKED`.

| Case | Outcome | Expected | Observed | Evidence reference | Residual risk |
| --- | --- | --- | --- | --- | --- |
| FUNC-01 | | | | | |
| ID-01 | | | | | |
| ID-02 | | | | | |
| REL-01 | | | | | |
| AUTH-01 | | | | | |
| ISO-01 | | | | | |
| ISO-02 | | | | | |
| ISO-03 | | | | | |
| REPO-01 | | | | | |
| NET-01 | | | | | |
| CRED-01 | | | | | |
| LIFE-01 | | | | | |
| LIFE-02 | | | | | |
| SESS-01 | | | | | |
| DATA-01 | | | | | |
| LIMIT-01 | | | | | |

## Operating cost

| Measure | Observed value |
| --- | --- |
| Human setup time | |
| Required accounts and credentials | |
| Privileged host changes | |
| Steady-state processes/containers | |
| Idle CPU and memory | |
| Update and pinning procedure | |
| Credential rotation procedure | |
| Crash recovery/manual repair | |
| Audit/evidence quality | |

## Decision

- P0 passed: `<count>/<total>`
- Unsupported, unobservable, or blocked P0 cases: `<list>`
- Candidate-specific assumptions: `<list>`
- Recommended project decision: `CONTINUE`, `PIVOT`, or `STOP`
- Reason: `<one evidence-backed paragraph>`
