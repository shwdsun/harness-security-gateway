# Security policy

## Project maturity

Harness Security Gateway is an independently developed, AI-assisted experiment
and reference project at the pre-alpha stage. It is not ready for production
use. Normal daemon configuration is mock-only; the separate opt-in provider
canary has two failed real Runs recorded on 2026-09-10. There is no public
Discord Connector or approved production Codex target. AI review is advisory;
the human maintainer owns security claims and release decisions. The limitations in
[`docs/implementation-status.md`](docs/implementation-status.md) are part of the
security claim.

## Reporting a vulnerability

Please use
[GitHub private vulnerability reporting](https://github.com/shwdsun/harness-security-gateway/security/advisories/new).
If that form is unavailable, open a public issue containing no vulnerability
details and ask the maintainer to establish a private channel. Never place an
unpatched vulnerability, real credential, private message, customer data, or
host dump in a public issue.

A useful report identifies:

- the affected revision and environment;
- the violated boundary or expected invariant;
- the smallest reproducible input or state transition;
- the observed durable state and side effects; and
- whether credentials, host paths, runtime sockets, or outbound recipients
  became reachable.

## Supported versions

Only the current `main` branch is considered for security fixes. No stable
release or compatibility guarantee exists yet.

## In scope

- authorization bypass or cross-Binding execution;
- replay that creates a second Run or external execution;
- Runner- or message-controlled image, path, command, mount, environment,
  credential, network, plugin, skill, or runtime selection;
- cross-Connector outbound disclosure or redirection;
- provider-session disclosure or cross-scope resume;
- runtime-socket exposure, containment escape, or unsafe create recovery; and
- sensitive details crossing a documented error or logging boundary.

## Out of scope for the current claim

- an absent Discord integration or disabled Codex target;
- production availability, multi-host operation, or high availability;
- model output quality or a model following hostile instructions when no
  deterministic authority boundary is crossed; and
- claims explicitly marked pending or unproved in the implementation status.

These exclusions do not make a suspected design flaw uninteresting. They only
prevent a missing feature from being mistaken for a regression in an enabled
security boundary.
