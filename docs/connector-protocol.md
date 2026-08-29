# Connector protocol v1

The Connector protocol is the narrow boundary between one platform account and
`agentd`. Each Connector instance receives one dedicated Unix socket. Selecting
that socket establishes `connector_id`; identity is never accepted in JSON, a
query parameter, or a request header.

On Linux, that endpoint also has one mandatory operator-configured peer UID.
`agentd` checks the kernel-recorded connect-time `SO_PEERCRED` UID inside the
listener before HTTP reads. A mismatch is closed with zero application bytes;
a credential-mechanism failure terminates the supervised listener. Non-Linux
builds refuse to serve. This code boundary does not by itself prove production
isolation: dedicated identities and the documented socket-directory ownership
contract remain deployment gates.

Transport is HTTP/1.1 with strict UTF-8 `application/json`. Duplicate keys,
unknown fields, trailing values, excessive nesting, and endpoint byte-limit
violations are rejected. V1 has three fixed `POST` operations.

## Ingest an observed event

`POST /v1/events/ingest`

```json
{
  "event_id": "discord-message-123",
  "actor_ref": "discord-user-456",
  "conversation_ref": "discord-channel-789",
  "message_ref": "discord-message-123",
  "occurred_at_unix_ms": 1786900000000,
  "content": {
    "type": "text",
    "text": "Inspect the project"
  }
}
```

`actor_ref`, `conversation_ref`, and `message_ref` are opaque values scoped to
this Connector instance. `agentd` never joins them into a path. For a new text
event, the endpoint-bound Connector, actor, and conversation must match one
operator-authored exact binding; that binding resolves directly to one immutable
TargetRevision. There is no independent actor/conversation set, route merge, or
message-selected target.

A `202 Accepted` is returned only after the inbox event and Run are committed
in one SQLite transaction:

```json
{
  "event_id": "discord-message-123",
  "disposition": "accepted",
  "run_id": "run_opaque"
}
```

Replaying the same `(connector instance, event_id)` and normalized payload while
its allow receipt is retained returns the original Run with
`disposition: "duplicate"`, without current re-authorization. Reusing a retained
event ID with changed content returns `event_conflict`. Once the
operator-selected `W_receipt` and durable eviction horizon remove the receipt,
the original event returns HTTP `410` with `event_expired`; it never recreates
or returns the old Run. HTTP `429` with `quota_exceeded` is transient and stores
no per-event decision. This is at-least-once ingestion with bounded Core
deduplication, not an exactly-once platform claim. The at-most-once boundary is
limited to the same non-rolled-back Core persistence lineage.

For a genuinely new event, HTTP `409` with `run_in_progress` means the exact
six-field Binding/session scope already has a `queued`, `dispatching`, or
`running` Run. The rejected event stores neither a receipt nor a Run. A retained
exact replay still returns its original Run before this current-state check;
the Connector must present a new event again only according to its explicit UX
and retry policy after the prior Run becomes terminal.

The current DTO recognizes a closed legacy `action` union (`status`, `cancel`,
and `select_target`) only so it can reject every member with
`action_unsupported`. This is not a compatibility promise or future grant;
`select_target` conflicts with exact Binding authorization and remains outside
the accepted target model.

## Claim outbound text

`POST /v1/deliveries/claim`

```json
{"limit": 10}
```

The Connector cannot choose lease duration. `agentd` returns at most the
requested bounded number of deliveries, and always emits an array:

```json
{
  "deliveries": [
    {
      "delivery_id": "delivery_opaque",
      "lease_token": "lease_capability",
      "lease_expires_unix_ms": 1786900030000,
      "conversation_ref": "discord-channel-789",
      "reply_to_ref": "discord-message-123",
      "content": {
        "media_type": "text/plain",
        "text": "Inspection complete"
      }
    }
  ]
}
```

The recipient is fixed by the original conversation/Run. A model or runner
cannot provide an arbitrary platform recipient. V1 is plain text only;
platform escaping, mention suppression, length splitting, and rate limiting
belong to the Connector.

## Complete one leased attempt

`POST /v1/deliveries/complete`

Success:

```json
{
  "delivery_id": "delivery_opaque",
  "lease_token": "lease_capability",
  "outcome": "delivered",
  "provider_message_ref": "discord-message-999"
}
```

Retryable failure:

```json
{
  "delivery_id": "delivery_opaque",
  "lease_token": "lease_capability",
  "outcome": "retry",
  "failure_class": "rate_limited"
}
```

Permanent failure:

```json
{
  "delivery_id": "delivery_opaque",
  "lease_token": "lease_capability",
  "outcome": "permanent_failure",
  "failure_class": "not_authorized"
}
```

Retry permits only `temporary_failure`, `rate_limited`, or
`connector_internal`. Permanent failure permits only
`recipient_unavailable`, `content_rejected`, `not_authorized`, or
`connector_internal`. Provider error text never crosses this boundary, and the
Connector cannot supply `retry_at`; `agentd` owns bounded exponential backoff.

A committed completion returns `204 No Content`. Completion is idempotent for
the same lease token and result while the bounded delivery record is retained,
including the normal response-loss retry. Inline compaction may remove a
terminal delivery after its parent Run's inbound receipt expires; a later
completion then returns `delivery_not_found`. A platform send can still succeed
immediately before the Connector process loses its response or crashes, so a
rare duplicate platform message remains possible.

## Evolution rules

- The `/v1/` path selects the schema; unknown V1 fields are not extension
  points.
- New platform-specific options are not passed through as maps.
- Attachments, buttons, native commands, and delivery receipts require a new
  reviewed closed union after a second real platform demonstrates the common
  semantics.
- Cell lifecycle/setup actions cannot appear in Connector v1. They require a
  new reviewed protocol only after Cell, Operation, action-specific policy, and
  lifecycle evidence exist. A platform menu is optional derived presentation,
  never an authority or a prerequisite for those semantics.
- Connector deployment (container or systemd sandbox) is not represented in
  this protocol.
