# Third-party notices

Harness Security Gateway uses third-party Go modules listed in `go.mod` and
`go.sum`. Those modules remain subject to their respective licenses.

No dependency source or compiled release binary is distributed in this
repository. The following modules were linked into at least one command by the
Go 1.26.7 release-candidate build:

| Module | Version | License |
| --- | --- | --- |
| `github.com/dustin/go-humanize` | v1.0.1 | MIT |
| `github.com/google/uuid` | v1.6.0 | BSD 3-Clause |
| `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748-24d4a6f8daec | BSD 3-Clause |
| `golang.org/x/sys` | v0.46.0 | BSD 3-Clause |
| `modernc.org/libc` | v1.74.1 | BSD 3-Clause, with bundled third-party notices |
| `modernc.org/mathutil` | v1.7.1 | BSD 3-Clause |
| `modernc.org/memory` | v1.11.0 | BSD 3-Clause, including bundled Go and mmap-go notices |
| `modernc.org/sqlite` | v1.54.0 | BSD 3-Clause |

The exact resolved module versions in `go.sum` are authoritative for a
particular build. Before distributing binaries, regenerate the linked-module
inventory and bundle the complete license and third-party notice texts from
those exact module versions. This summary is not a substitute for those texts.
