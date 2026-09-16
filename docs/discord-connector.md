# Private Discord Connector v1

Status: **implemented and offline-tested; no bot token, live channel or
deployment identity is part of this code.** It is the first real platform
Connector and remains disabled until its own gates below pass.

This Connector owns exactly one platform account, one allowlisted channel and
one dedicated `agentd` Unix socket. It has no listening port, no Core database
access, no workspace, no runtime socket and no model credential. Discord cannot
select a target, alias, image, path, command or any runtime option: the event
carries only stable platform facts and normalized text, exactly like the
existing fake Connector.

## Ingress transport decision

V1 polls Discord's REST API instead of connecting to the Gateway WebSocket.

A Gateway callback is not accepted as durable ingress: its `RESUME` recovers
transport delivery, not the Connector's at-least-once handoff to Core. The
required design is a Connector-owned private cursor with bounded catch-up, and
polling expresses exactly that with no extra moving parts:

- the platform itself retains history, so the Connector needs no second copy of
  message bodies;
- one monotone cursor per channel is the whole ingress state;
- catch-up after any downtime is the same code path as steady state;
- no WebSocket dependency, heartbeat, session resume, shard or zlib handling
  enters the module, which keeps its two existing dependencies.

The cost is latency bounded by the poll interval and one request per interval.
For a single private channel this is a deliberate trade: predictable, restartable
ingress over minimum latency. A Gateway ingress would need its own reviewed
dependency, and would still need this cursor to be durable.

## Identity normalization

Discord snowflake IDs are stable and never reused, so they are the normalized
identity source. The Connector emits only these forms:

| Wire field | Value |
| --- | --- |
| `event_id` | `discord:message:<message id>` |
| `message_ref` | `discord:message:<message id>` |
| `actor_ref` | `discord:user:<author id>` |
| `conversation_ref` | `discord:channel:<channel id>` |
| `occurred_at_unix_ms` | Snowflake creation time, `(id >> 22) + 1420070400000` |

The snowflake timestamp is used rather than the local clock or `timestamp`
string because it is a stable platform event time that cannot change on retry,
which the replay contract requires. Operator bindings therefore use exactly
these strings; the Connector never normalizes or rewrites a ref to fit a binding.

## Admission filters before Core

A message is dropped, without an event and without advancing past it silently,
unless all hold:

- its channel equals the single configured channel;
- its author ID is in the configured allowlist of stable user IDs;
- the author is not the Connector's own account, and is not a bot or webhook;
- the message type is a normal message or reply;
- the content is non-empty after trimming and within the wire text bound.

Bot, webhook and self filtering is the Connector's half of self-loop protection;
`agentd` independently rejects its configured `self_actor_ref`. Empty content is
also what an unprivileged bot sees when the Message Content intent is missing,
so it is treated as nothing to admit rather than an empty prompt.

## Durable cursor and bounded catch-up

The Connector keeps one private SQLite database, in its own domain:

```text
cursor(channel_id PRIMARY KEY, last_message_id)
sent_deliveries(delivery_id PRIMARY KEY, provider_message_ref, sent_at_unix_ms)
```

Each poll requests at most `catch_up_limit` messages after the cursor, oldest
first. For every message the Connector ingests first and advances the cursor
only after `agentd` durably acknowledges it, including a `duplicate`
disposition. A crash before that acknowledgement therefore re-presents the same
message with the same event ID, which Core deduplicates while its receipt is
retained. This is at-least-once handoff with bounded catch-up, not an
exactly-once claim.

A filtered-out message still advances the cursor, because it can never become
admissible later. On first start with no cursor, the Connector adopts the
channel's latest message as the cursor and admits nothing, so deploying it never
replays channel history.

Backlog is bounded per poll, so a flood cannot turn into an unbounded burst of
admissions; Core's own per-Connector quotas remain the enforcing limit.

## Outbound delivery

The Connector claims a bounded batch, sends each reply and completes the lease:

- the recipient always comes from the delivery's `conversation_ref`, which Core
  derives from the parent Run. A reply target is never taken from model output;
- `allowed_mentions` is sent with empty parse arrays, so a reply can never ping
  a user, role or everyone regardless of its text;
- text longer than one Discord message is split into ordered chunks up to a
  configured maximum; the first chunk's ID becomes `provider_message_ref`;
- before completing, the Connector durably records the delivery ID it sent. If
  the same delivery is re-leased after a crash or lost response, it completes
  from that record instead of sending again.

Failures map to the closed protocol classes, and provider error text never
crosses the boundary:

| Discord result | Outcome | Class |
| --- | --- | --- |
| 2xx | `delivered` | — |
| 429, 500, 502, 503, 504, transport error | `retry` | `rate_limited` or `temporary_failure` |
| 401, 403 | `permanent_failure` | `not_authorized` |
| 404 (channel gone) | `permanent_failure` | `recipient_unavailable` |
| 400, 413 | `permanent_failure` | `content_rejected` |
| anything else | `permanent_failure` | `connector_internal` |

`agentd` owns backoff; the Connector never supplies a retry time, and it honours
Discord's own `Retry-After` only for its own pacing, described next.

## Pacing and unattended operation

The Connector runs with no operator present, so it must not hammer a platform
that is refusing it. Each cycle is scheduled after the previous one finishes
rather than on a fixed tick, and a failed pass pauses the next one:

- consecutive failures back off geometrically from the configured poll
  interval, over a bounded number of steps;
- a `429` extends that pause to the `Retry-After` the platform asked for;
- `Retry-After` is untrusted platform data, so it can lengthen the pause but
  never shorten it, and it is clamped — a hostile or faulty header cannot park
  the Connector indefinitely;
- a healthy pass resets the backoff.

This applies to ingress as well as delivery. Rate limiting the outbound path
alone would be insufficient, because polling is the request the Connector makes
most often.

The Connector also reports bounded counters whenever they change, no more often
than once every five minutes. The counters are the closed skip labels and the
admitted and delivered counts; they carry no message content, author,
identifier or platform text. Their operational purpose is specific: a platform
application without the message-content intent returns empty text for every
message, so the Connector skips everything and otherwise looks perfectly
healthy. `skipped=empty_content=N` with `admitted=0` is that condition.

`discord-connector -check` loads the configuration and the token file and then
stops. It opens no state database, contacts no local peer and makes no platform
request, so an installation can be rejected for a malformed configuration, an
out-of-range bound or a token file another identity could read before anything
runs as the Connector.

## Token handling

The bot token is read once from an operator-provisioned file that must be a
regular, single-link, non-group/other-readable file owned by the Connector
identity. It is held only in memory, sent only as an `Authorization: Bot` header
to the configured API origin, and never logged, echoed into an event, written to
the state database or included in an error. The configuration accepts only an
`https` origin at Discord's API host, so a redirected or plaintext origin cannot
receive it.

## Platform payload parsing

Our own contracts use strict closed decoding. Discord's responses are an
external API that adds fields over time, so they are parsed leniently within a
bounded read, and only the allowlisted fields above are used. Every value then
passes the normal wire validation before it can become an event, so an unknown
or hostile field cannot reach Core.

## Deployment

The Connector runs as its own locked system identity, distinct from Core and the
sandbox owner, with its own private state and credential directory and access to
only its own `agentd` socket. It needs no inbound network, no container runtime
and no sandbox path.

The operator must separately: create the application and bot, enable the Message
Content intent for it, invite it to one private server with only View Channel,
Read Message History and Send Messages, and record the exact channel, bot and
author IDs into the binding and this configuration.

## What this does not establish

- No live channel, token or deployment identity is exercised by the offline
  tests. Four real Runs and the one-live-Run fence have since passed on one
  host — see [implementation status](implementation-status.md).
- The deployed conversation is a direct message, which Discord closes to two
  accounts and gives no webhooks. Every foreign-author case is therefore
  structurally absent there and keeps offline evidence only; multi-member
  channel filtering has no live witness.
- Deterministic adversarial cases and a deny audit run offline against the real
  compiled policy, admission service and Core store, with only the platform
  faked. The isolated cases against a live private channel, quota calibration
  under real traffic and the bake-off remain open; a passing send/receive path
  is not evidence for them.
- Attachments, embeds, buttons, slash commands, reactions, edits, deletions,
  threads and multi-channel operation are deliberately unimplemented.
- Message edits after admission are not tracked: an admitted event is frozen by
  its Run, and a later edit is not a new event.
- **Known defect.** An ingest refusal leaves the cursor where it is so the
  message is presented again. That is right for a transient refusal and wrong
  for a permanent one: `event_expired` can never succeed, so one message older
  than Core's accept window wedges the cursor and everything behind it. An
  outage longer than that window leaves an unattended Connector unable to admit
  anything until an operator moves the cursor by hand. `PollOnce` must classify
  Core's permanent refusals and treat them like a normalization skip.
