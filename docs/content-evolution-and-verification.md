# Content evolution and verification scope

Adopted **2026-09-09 UTC**. This is an evolution and engineering contract;
implemented V1 interfaces remain text-only, and the real target remains blocked.
The synthetic V3 composition and opt-in provider canary have since advanced;
[implementation status](implementation-status.md) records their dated evidence
and remaining gates. Images, files, a new wire schema or artifact storage are
not implemented by this decision.

## Stable obligations and extension boundaries

One admitted Run carries typed task content. Identity, Binding/target scope,
replay, cancellation and cleanup rules apply independently of its media type.
New resources still need explicit ownership and lifetime enforcement.

| Owner | Stable obligation | Content extension belongs here |
| --- | --- | --- |
| Connector | Authenticated platform facts and delivery to the admitted destination | Normalize platform content and present supported output |
| Core | Admission, Run identity, payload identity, replay and disclosure scope | Carry the validated content manifest; keep media decoding and file fetching outside Core |
| Sandbox/runtime owner | Resolve authorized resources, contain execution and prove cleanup | Stage/pin authorized input objects, deliver them to the Runner and enforce their resource/lifetime policy |
| Runner adapter | Translate an admitted task into the fixed native harness contract | Map supported content types to native input/output; reject unsupported types without fallback or wider authority |

Current [execution input](../internal/executionwire/types.go),
[Core storage](../internal/corestore/types.go) and
[Runner content](../internal/runnerwire/types.go) still contain text-specific
types. First attachment support therefore needs a coordinated protocol/storage/
adapter change. The intended extension is a versioned closed content union,
with text and typed attachment references; no generic provider-option map or
per-format branch in authorization/recovery. Exact schema and migration belong
to the first authorized media implementation. Existing V1 rejection and replay
semantics must remain stable across that upgrade.

The [synthetic Responses limits](codex-control-boundary.md#first-enforcement-consumer-synthetic-responses)
belong to that fixture policy. They are not universal media limits. Future
limits must be explicit in the versioned target/content contract and tested there.

Attachment references must be checked against the authorized input/output scope.
Bind a canonical content manifest, including meaningful order, type, size and
object digest, into replay identity. A digest proves content identity, not
permission; a message-supplied path, URL or MIME label cannot grant access.
The trusted owner selects any storage location, fetch capability or native path.

First attachment support must specify input staging/pinning/release, byte and
count limits, cancellation/crash behavior, and output retention/delivery failure.
Outputs may need bounded retention after runtime cleanup; retention cannot keep
execution authority alive. Reuse lifecycle rules only where their assumptions
still hold. A new upload service or independently surviving resource is a new
ownership obligation, not merely another content tag.

## Change impact determines verification

| Change | Required incremental work and checks |
| --- | --- |
| Documentation only | Review meaning, links and formatting; no automatic Go, solver, model-review or runtime rerun |
| Presentation or a format through an existing content path | Validate affected output, type/limits and adapter compatibility; reuse shared content/lifecycle tests, adding decoder/resource checks if a decoder changes |
| First attachment path or new wire/storage revision | Check closed decoding, migration/legacy replay, content identity, reference scope, ownership and failure cleanup; exercise a thin complete input/output path |
| New parser, external fetch, upload operation, mount, credential route or runtime image | Review the changed authority/resource assumptions and test their rejection/progress cases; renew affected native/composition evidence |
| Change admission, replay, recovery, cleanup or publication semantics | Run affected transaction/property regressions; revisit relevant formal model assumptions and code mapping, then affected integration cases |

Rows compose when a change crosses boundaries. A small diff can change authority;
a broad mechanical type migration can leave lifecycle semantics intact. Describe
the affected guarantees before selecting checks, rather than using diff size or
file extension as the risk classification.

During editing, use focused checks. For a coherent Go change, retain the normal
repository test/race/vet requirements; automatic regression may run broadly and
reuse valid caches. Run costly native/remote experiments when their composed
consumer is ready or changed dependencies require them. Preserve failures and
diagnose before retrying. Required checks and operator authorizations still apply.

## Reuse evidence with explicit dependencies

Carry forward a result only for the claim whose code, contract and environmental
assumptions still apply. Keep its original date and scope. A documentation or
unrelated content change does not invalidate every earlier result. A new image
digest does require renewed artifact attestation and affected composition checks;
unchanged mechanism tests and design rationale need not be recreated. Unsupported
environments, skips and missing evidence do not become passes through reuse.

The [recovery pilot](../formal/recovery/README.md#model-to-code-mapping) abstracts
specific recovery state and assumes exact cleanup. Content variants that preserve
those semantics do not require a new proof. New resource lifetimes or transaction
semantics require checking the mapping and assumptions; proof over the old model
cannot establish file delivery, parser safety or native containment.

In the existing PR/task/operation note, record four short items:

1. Changed behavior/contracts and affected guarantees.
2. Reused evidence and why its assumptions still hold.
3. Selected checks and the trigger for any costly experiment or new review.
4. Results and remaining limits.

Keep this proportional: a documentation edit needs a short note, not another
standalone research stage or a complete archive of unchanged source. Consolidate
acceptance around the integrated delivery; keep individual component results as
its supporting evidence.

Prepare one coherent work package through design, implementation, affected
checks, candidate artifacts and a reviewable execution preview. These are not
separate approval boundaries. Reuse standing authorization for local work and
effects already covered by the task; obtain approval for any new external
effect outside that scope after its concrete preparation is complete. An
operator may authorize a bounded test campaign with explicit Run count, effects,
allowed changes and stop conditions. Preview and record each effect; a new
artifact or model recommendation cannot silently widen that authorization.

Commit a coherent, verified local work package with its remaining gates recorded.
An unresolved external compatibility result need not delay a source checkpoint.
Keep checkpoint completion separate from product acceptance and release, and
avoid accumulating several completed packages as one uncommitted working tree.

A diagnostic experiment should distinguish the remaining hypotheses with
bounded, non-secret observations before spending another real attempt. A useful
failed test can identify a specific rejection and verify cleanup; it does not
establish product acceptance. Count side effects at their actual admission
boundary: one Run may contain multiple provider requests, concurrent work already
authorized before a rejection differs from work authorized afterward, and HTTP
status alone is not authentication or model-completion evidence. Formal models
and synthetic fixtures retain their stated assumptions; neither substitutes for
the affected live compatibility observation.

## Stage ordering

The previous requirement to wait for a second real platform or both Codex and
Claude text conformance before considering attachments is superseded. A concrete
authorized user path and its security/compatibility evidence determine that scope.
This removes an unrelated sequencing dependency, not the current feature freeze,
closed-schema requirements, real-target gates or deployment authorization rules.
