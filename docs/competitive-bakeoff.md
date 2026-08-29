# Competitive security bake-off

Status: protocol prepared; live candidate runs have not yet been executed.

## Purpose

This bake-off compares the security and operating properties of existing
messaging-to-harness systems. It is not a feature-count comparison and its
documentation review is not evidence of a pass.

The canonical cases are in [`bakeoff/cases.json`](../bakeoff/cases.json). Copy
[`bakeoff/result-template.md`](../bakeoff/result-template.md) for each candidate
and deployment profile.

## Candidates and profiles

Each candidate is tested twice where supported: first with the documented
quick-start/default profile, then with the strongest practical hardened profile.
Do not combine the results.

| Candidate | Default profile | Hardened profile |
| --- | --- | --- |
| Claude Code Channels | Official Discord quick start | Static sender allowlist, DM-only, strict permissions, sandbox fail-closed |
| OpenClaw | Official Discord quick start | Sender allowlist, sandbox `all`, no elevated tools, reviewed binds and egress |
| NanoClaw | Pinned core plus pinned Discord/Codex additions | Per-agent isolation, reviewed mounts, credential vault/proxy, constrained egress |
| Harness Security Gateway | Not eligible until the real slice exists | Private Discord plus immutable Codex target and all P0 controls |

Current official documentation establishes useful baselines:

- [Claude Code Channels](https://code.claude.com/docs/en/channels) is a research
  preview in which a Channel runs as an MCP subprocess of a live Claude Code
  session. Its [Channels reference](https://code.claude.com/docs/en/channels-reference)
  emphasizes sender-ID gating. It is the minimum-setup UX baseline, not an
  independent Connector isolation boundary.
- [OpenClaw's security model](https://docs.openclaw.ai/gateway/security) treats
  one Gateway as one trusted operator boundary. Its
  [sandbox](https://docs.openclaw.ai/gateway/sandboxing) is configurable but is
  not the default execution model.
- [NanoClaw](https://github.com/nanocoai/nanoclaw) uses containerized agents,
  fixed mounts, and optional credential handling. Its published
  [security model](https://github.com/nanocoai/nanoclaw/blob/main/docs/SECURITY.md)
  must be checked against the exact pinned source because channel and provider
  additions may have separate installation histories.

### Candidate-specific baselines

#### Claude Code Channels

Record the exact Claude Code version and official plugin marketplace commit.
Run the official Discord quick start as the default profile. Before using an
external bot, use the official
[Fakechat Channel](https://github.com/anthropics/claude-plugins-official/blob/main/external_plugins/fakechat/README.md)
to separate Channel startup failures from Discord and provider failures.

The hardened profile uses numeric Discord user IDs, `allowlist` with
`DISCORD_ACCESS_MODE=static`, DM-only routing, sandbox `enabled` with
`failIfUnavailable`, and both Claude Read deny rules and sandbox filesystem deny
rules for every forbidden path. Do not use `-p`, `bypassPermissions`,
`--dangerously-skip-permissions`, or development-channel bypass flags.

Record as architectural facts, not test failures: the Channel is an MCP child
of a live Claude Code session; the Discord token and Claude Code share an OS
trust domain; any allowlisted permission-relay user can approve tools; project
trust and MCP consent still require local confirmation.

#### OpenClaw

Pin [release `v2026.7.1-2`](https://github.com/openclaw/openclaw/releases/tag/v2026.7.1-2)
and verify Git commit
`0790d9f593ad30c940ed93b5872a8cf6d6f3cf8c`; do not mix release code with
moving `main` documentation or images. Pin the lockfile, Discord plugin, Codex
package, and final image RepoDigest.

Phase A validates messaging and policy with no coding authority: local/loopback
Gateway, token authentication, numeric Discord allowlists, exact guild/channel
IDs, group DMs and administrative commands disabled, explicit plugin allowlist,
minimal tools, no exec/elevated access, and sandbox `all` with network none,
read-only root, all capabilities dropped, tmpfs, and resource limits.

Only after Phase A passes may Phase B expose the synthetic repository with
workspace-only write access and coding tools. Continue to deny web, UI, nodes,
plugins, automation, sessions, host exec, and elevated mode. Do not use
`openclaw agent exec` for isolation evidence: that path is documented to run on
the Gateway host. OpenClaw's Gateway and native plugins remain outside its tool
sandbox, and Docker-socket access makes the Gateway a daemon principal; the
disposable VM remains the outer boundary.

#### NanoClaw

Pin release [`v2.3.0`](https://github.com/nanocoai/nanoclaw/releases/tag/v2.3.0)
at Git commit `54d9d9a50c0e572fa3969d63ab87a4dd3d75cc6f`. Record the
core SHA, package-lock hash, image digest, exact `/add-discord` and `/add-codex`
inputs, and the complete post-install source/lockfile diff. The release changes
container-runtime and credential handling, so results from v2.2.0 are not
substitutes. Never treat a moving branch or an agent-applied install change as a
reproducible pin.

The hardened profile uses OneCLI Vault rather than native credentials,
`NANOCLAW_EGRESS_LOCKDOWN=true`, no additional mounts, external MCPs,
destinations, tasks, or broad skills, `cli_scope=disabled`, explicit CPU/memory/
PID limits, strict unknown-sender drop, numeric IDs, and a separate agent group
per Discord trust domain. Inspect the first live container rather than assuming
the documented user, capabilities, root filesystem, mounts, or network.

Record as architectural facts: one host Node process holds channel tokens,
routing/SQLite state, and Docker lifecycle authority; agent containers live per
session rather than per Run; threads in one agent group share workspace, memory,
configuration, and credential grants; tool egress is open unless lockdown is
explicitly enabled.

## Lab isolation

Competitive software must not be installed on a workstation or server that
contains personal credentials or production data.

For every candidate/profile combination:

1. Use a fresh disposable VM with a unique OS account.
2. Use a dedicated Discord bot, test guild, test users, and low-value provider
   account or credential. Never copy personal SSH keys, browser state, or a
   production repository into the VM.
3. Generate only fake canaries with `bakeoff/fixtures/prepare.sh`. The external
   collector, if used, must be a separate lab-only address.
4. Record package versions, Git commits, image digests, plugins, skills, and
   provider additions. Review installer changes before executing them.
5. Export redacted evidence, revoke credentials, and destroy the VM after the
   profile is complete.

### Lab prerequisites

Before live execution, prepare:

- one disposable x86-64 Linux VM that can be reset to a clean snapshot between
  every candidate/profile (recommended minimum: 4 vCPU, 8 GiB RAM, 40 GiB
  disk), with outbound internet, SSH/console access, and no production data;
- preferably a second, isolated lab collector for HTTPS/DNS egress evidence;
- a private Discord test guild, dedicated bot applications/tokens, one
  authorized human account, and a distinct unauthorized human account;
- a revocable, budget-capped provider credential for each candidate. Claude
  Code Channels additionally needs supported Claude Code access. If that is not
  available, its live profile is `BLOCKED`, not silently substituted;
- the ability to revoke all tokens and destroy or restore the VM after a run.

No public inbound endpoint is required for Discord Gateway-based profiles. A
primary personal model login should not be used inside unreviewed competitor
software. An API-key-only result also cannot be claimed as proof that a
subscription-login credential is isolated.

## Evidence rules

Allowed outcomes are `PASS`, `FAIL`, `NOT_SUPPORTED`, `NOT_OBSERVABLE`, and
`BLOCKED`. `NOT_OBSERVABLE` and `BLOCKED` are not passes.

For every case record:

- exact candidate/profile/version and configuration digest;
- sender, conversation, and provider message IDs where applicable;
- commands or API calls, UTC timestamps, and exit status;
- relevant redacted logs, process/container inventory, filesystem observations,
  and network observations;
- expected and observed result plus the outcome;
- deviations from the official default and residual authority.

Never put a real token, reusable provider session, raw environment dump, or
private prompt transcript in the evidence bundle.

## Execution order

Run the cases in this order so a basic setup failure is not confused with a
security result:

1. Baseline function: authorized text request, response, and documented resume.
2. Identity and replay: unauthorized senders, identity collision, duplicates.
3. Authority isolation: Connector, control plane, Runner, and target admission.
4. Repository and egress: hooks, project configuration, symlinks, canaries, and
   network destinations.
5. Lifecycle faults: cancellation, process-tree cleanup, restart, replay, and
   uncertain runtime state.
6. Operational review: install/update surface, secret rotation, backup, audit,
   and measured maintenance cost.

## Hard gates

The Harness Security Gateway real slice is not eligible for additional platforms or
Harnesses until it passes every P0 case. In particular:

- a compromised Connector cannot read a workspace, model login, Core database,
  another platform token, or any container-runtime socket;
- a message cannot choose or inject execution authority outside an immutable
  approved target;
- replay cannot create a second writable Run or duplicate side effect;
- repository content cannot activate hooks, plugins, MCP, skills, or escape by
  symlink;
- model traffic still works while tool-controlled arbitrary internet, LAN, host,
  and metadata access is denied;
- model-controlled code cannot recover a reusable provider credential;
- cancellation and crashes cannot leave a live process/container, unlock early,
  or silently retry an uncertain writable Run.

## Decision

After all candidate profiles are measured, write one of:

- `CONTINUE`: Harness Security Gateway demonstrates a material, repeatable isolation or
  lifecycle property missing from simpler alternatives.
- `PIVOT`: an existing implementation is adequate; retain only useful security
  tests, adapters, or documentation.
- `STOP`: the added security property is not achieved or its operating cost is
  not justified for the intended personal deployment.

The decision is based on observed security properties and operating cost, not
on the number of supported channels or Harnesses.
