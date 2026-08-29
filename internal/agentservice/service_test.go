package agentservice

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
	"github.com/shwdsun/harness-security-gateway/internal/agentpolicy"
	"github.com/shwdsun/harness-security-gateway/internal/connectorhttp"
	"github.com/shwdsun/harness-security-gateway/internal/connectorwire"
	"github.com/shwdsun/harness-security-gateway/internal/corestore"
)

type fakeStore struct {
	ingestFn func(
		context.Context,
		corestore.IngestTextRunInput,
		corestore.TextRunAuthorizer,
		corestore.RunIDSource,
	) (corestore.IngestResult, error)
	claimFn    func(context.Context, string, int, time.Duration) ([]corestore.TextDelivery, error)
	completeFn func(context.Context, corestore.CompleteDeliveryInput) error

	ingestInputs   []corestore.IngestTextRunInput
	authorizations []corestore.TextRunAuthorization
	ingestRunIDs   []string
	claimInputs    []claimCall
	completeInputs []corestore.CompleteDeliveryInput
}

type claimCall struct {
	connectorID string
	limit       int
	lease       time.Duration
}

func (s *fakeStore) IngestTextRun(
	ctx context.Context,
	input corestore.IngestTextRunInput,
	authorize corestore.TextRunAuthorizer,
	newRunID corestore.RunIDSource,
) (corestore.IngestResult, error) {
	s.ingestInputs = append(s.ingestInputs, input)
	if s.ingestFn != nil {
		return s.ingestFn(ctx, input, authorize, newRunID)
	}
	authorization, err := authorize()
	if err != nil {
		return corestore.IngestResult{}, err
	}
	runID, err := newRunID()
	if err != nil {
		return corestore.IngestResult{}, err
	}
	s.authorizations = append(s.authorizations, authorization)
	s.ingestRunIDs = append(s.ingestRunIDs, runID)
	return corestore.IngestResult{Run: corestore.Run{ID: runID}}, nil
}

func (s *fakeStore) ClaimTextDeliveries(ctx context.Context, connectorID string, limit int, lease time.Duration) ([]corestore.TextDelivery, error) {
	s.claimInputs = append(s.claimInputs, claimCall{connectorID: connectorID, limit: limit, lease: lease})
	if s.claimFn != nil {
		return s.claimFn(ctx, connectorID, limit, lease)
	}
	return nil, nil
}

func (s *fakeStore) CompleteDelivery(ctx context.Context, input corestore.CompleteDeliveryInput) error {
	s.completeInputs = append(s.completeInputs, input)
	if s.completeFn != nil {
		return s.completeFn(ctx, input)
	}
	return nil
}

func validPolicyConfig() agentconfig.Config {
	return agentconfig.Config{
		Schema: agentconfig.SchemaV3, Database: "/var/lib/hgw/agentd.sqlite3",
		SandboxSocket: "/run/hgw/sandboxd.sock", RunTimeoutSeconds: 300,
		DeliveryLeaseSeconds: 30, RunDispatchLeaseSeconds: 30,
		Ingress: agentconfig.Ingress{
			AcceptWindowSeconds: 300, ReceiptWindowSeconds: 3600,
			FutureSkewSeconds: 60, MaxReceiptsPerConnector: 128,
			MaxQueuedRunsPerConnector: 16, MaxNonTerminalRunsPerConnector: 32,
			MaxPendingDeliveriesPerConnector:  128,
			MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16_384,
		},
		Connectors: []agentconfig.Connector{{
			ID: "discord-main", Socket: "/run/hgw/connectors/discord/agentd.sock",
			PeerUID: 1000, SelfActorRef: "discord:bot:1",
		}},
		Bindings: []agentconfig.Binding{{
			ID: "discord-private", ConnectorID: "discord-main",
			ActorRef: "discord:user:100", ConversationRef: "discord:channel:200",
			Target: agentconfig.TargetRef{ID: "codex", Revision: "codex-2026-08"},
		}},
	}
}

func validEndpoint() agentpolicy.Endpoint {
	policy, err := agentpolicy.Compile(validPolicyConfig())
	if err != nil {
		panic(err)
	}
	endpoint, err := policy.Endpoint("discord-main")
	if err != nil {
		panic(err)
	}
	return endpoint
}

func validTextEvent() connectorwire.InboundEventV1 {
	return connectorwire.InboundEventV1{
		EventID:          "discord:event:300",
		ActorRef:         "discord:user:100",
		ConversationRef:  "discord:channel:200",
		MessageRef:       "discord:message:400",
		OccurredAtUnixMS: 1_800_000_000_123,
		Content: connectorwire.InboundContentV1{
			Type: connectorwire.ContentTypeText,
			Text: "please inspect the workspace",
		},
	}
}

func sequentialRunIDs() RunIDSource {
	next := 0
	return func() (string, error) {
		next++
		return fmt.Sprintf("run_test_%d", next), nil
	}
}

func newTestService(t *testing.T, endpoint agentpolicy.Endpoint, store Store) *Service {
	t.Helper()
	service, err := NewWithRunIDSource(endpoint, 45*time.Second, store, sequentialRunIDs())
	if err != nil {
		t.Fatalf("NewWithRunIDSource: %v", err)
	}
	return service
}

func requireServiceErrorCode(t *testing.T, err error, expected connectorhttp.ErrorCode) *connectorhttp.ServiceError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected service error %q, got nil", expected)
	}
	var serviceError *connectorhttp.ServiceError
	if !errors.As(err, &serviceError) {
		t.Fatalf("expected *connectorhttp.ServiceError, got %T: %v", err, err)
	}
	if serviceError.Code != expected {
		t.Fatalf("error code = %q, want %q", serviceError.Code, expected)
	}
	if got, want := serviceError.Error(), "connector service error: "+string(expected); got != want {
		t.Fatalf("closed error text = %q, want %q", got, want)
	}
	return serviceError
}

func TestIngestEnforcesExactBindingWithoutCartesianProduct(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	service := newTestService(t, validEndpoint(), store)

	tests := []struct {
		name   string
		mutate func(*connectorwire.InboundEventV1)
	}{
		{
			name: "actor",
			mutate: func(event *connectorwire.InboundEventV1) {
				event.ActorRef = "discord:user:999"
			},
		},
		{
			name: "conversation",
			mutate: func(event *connectorwire.InboundEventV1) {
				event.ConversationRef = "discord:channel:999"
			},
		},
		{
			name: "conversation prefix is not authority",
			mutate: func(event *connectorwire.InboundEventV1) {
				event.ConversationRef += ":thread"
			},
		},
		{
			name: "connector self actor",
			mutate: func(event *connectorwire.InboundEventV1) {
				event.ActorRef = "discord:bot:1"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := validTextEvent()
			test.mutate(&event)
			_, err := service.Ingest(context.Background(), event)
			requireServiceErrorCode(t, err, connectorhttp.ErrorForbidden)
		})
	}
	if got := len(store.ingestInputs); got != len(tests) {
		t.Fatalf("unauthorized normalized events reached replay boundary %d times, want %d", got, len(tests))
	}
	if got := len(store.ingestRunIDs); got != 0 {
		t.Fatalf("unauthorized events minted %d Run IDs", got)
	}
}

func TestIngestCannotUseAnotherConnectorBinding(t *testing.T) {
	t.Parallel()
	config := validPolicyConfig()
	config.Connectors = append(config.Connectors, agentconfig.Connector{
		ID: "matrix-main", Socket: "/run/hgw/connectors/matrix/agentd.sock",
		PeerUID: 1001, SelfActorRef: "matrix:bot:1",
	})
	config.Bindings = append(config.Bindings, agentconfig.Binding{
		ID: "matrix-private", ConnectorID: "matrix-main",
		ActorRef: "matrix:user:100", ConversationRef: "matrix:room:200",
		Target: agentconfig.TargetRef{ID: "claude", Revision: "claude-2026-08"},
	})
	policy, err := agentpolicy.Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	discordEndpoint, err := policy.Endpoint("discord-main")
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	service := newTestService(t, discordEndpoint, store)
	event := validTextEvent()
	event.ActorRef = "matrix:user:100"
	event.ConversationRef = "matrix:room:200"
	_, err = service.Ingest(context.Background(), event)
	requireServiceErrorCode(t, err, connectorhttp.ErrorForbidden)
	if len(store.authorizations) != 0 || len(store.ingestRunIDs) != 0 {
		t.Fatalf("cross-connector binding produced authority: auth=%#v ids=%#v",
			store.authorizations, store.ingestRunIDs)
	}
}

func TestServiceUsesCompiledImmutableBindingEvidence(t *testing.T) {
	t.Parallel()
	config := validPolicyConfig()
	policy, err := agentpolicy.Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policy.Endpoint("discord-main")
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	service := newTestService(t, endpoint, store)

	config.Connectors[0].ID = "attacker-selected"
	config.Connectors[0].SelfActorRef = "discord:user:100"
	config.Bindings[0].ActorRef = "discord:user:999"
	config.Bindings[0].Target = agentconfig.TargetRef{ID: "other", Revision: "other-revision"}

	receipt, err := service.Ingest(context.Background(), validTextEvent())
	if err != nil {
		t.Fatalf("Ingest after source mutation: %v", err)
	}
	if receipt.Disposition != connectorwire.InboundAccepted {
		t.Fatalf("disposition = %q, want accepted", receipt.Disposition)
	}
	if got := len(store.ingestInputs); got != 1 {
		t.Fatalf("ingest calls = %d, want 1", got)
	}
	input := store.ingestInputs[0]
	if input.ConnectorID != "discord-main" {
		t.Fatalf("bound connector ID = %q", input.ConnectorID)
	}
	if len(store.authorizations) != 1 || store.authorizations[0].TargetID != "codex" ||
		store.authorizations[0].TargetRevision != "codex-2026-08" ||
		len(store.authorizations[0].BindingFingerprint) != corestore.SHA256HexBytes ||
		store.authorizations[0].PolicyRevision != policy.Revision() {
		t.Fatalf("compiled binding evidence = %#v", store.authorizations)
	}
}

func TestExactBindingEvidencePersistsAcrossServiceAndCore(t *testing.T) {
	config := validPolicyConfig()
	config.Connectors = append(config.Connectors, agentconfig.Connector{
		ID: "matrix-main", Socket: "/run/hgw/connectors/matrix/agentd.sock",
		PeerUID: 1001, SelfActorRef: "matrix:bot:1",
	})
	config.Bindings = append(config.Bindings, agentconfig.Binding{
		ID: "matrix-private", ConnectorID: "matrix-main",
		ActorRef: "matrix:user:100", ConversationRef: "matrix:room:200",
		Target: agentconfig.TargetRef{ID: "claude", Revision: "claude-2026-08"},
	})
	policy, err := agentpolicy.Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policy.Endpoint("discord-main")
	if err != nil {
		t.Fatal(err)
	}
	event := validTextEvent()
	store, err := corestore.Open(context.Background(), filepath.Join(t.TempDir(), "agentd.sqlite3"), corestore.Options{
		Clock: func() time.Time { return time.UnixMilli(event.OccurredAtUnixMS) },
		Admission: corestore.AdmissionOptions{
			AcceptWindow: 5 * time.Minute, ReceiptWindow: time.Hour, FutureSkew: time.Minute,
			MaxReceiptsPerConnector: 128, MaxQueuedRunsPerConnector: 16,
			MaxNonTerminalRunsPerConnector: 32, MaxPendingDeliveriesPerConnector: 128,
			MaxRetainedInputBytesPerConnector: 4 << 20, MaxDatabasePages: 16_384,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runIDCalls := 0
	service, err := NewWithRunIDSource(endpoint, 30*time.Second, store, func() (string, error) {
		runIDCalls++
		return fmt.Sprintf("run_integration_%d", runIDCalls), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := service.Ingest(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	run, err := store.GetRun(context.Background(), receipt.RunID)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := endpoint.Authorize(event.ActorRef, event.ConversationRef)
	if err != nil {
		t.Fatal(err)
	}
	if run.TargetID != decision.TargetID || run.TargetRevision != decision.TargetRevision ||
		run.BindingFingerprint != decision.BindingFingerprint || run.PolicyRevision != decision.PolicyRevision {
		t.Fatalf("persisted Run evidence = %#v, decision = %#v", run, decision)
	}

	crossConnector := event
	crossConnector.EventID = "discord:event:cross-connector"
	crossConnector.MessageRef = "discord:message:cross-connector"
	crossConnector.ActorRef = "matrix:user:100"
	crossConnector.ConversationRef = "matrix:room:200"
	_, err = service.Ingest(context.Background(), crossConnector)
	requireServiceErrorCode(t, err, connectorhttp.ErrorForbidden)
	if runIDCalls != 1 {
		t.Fatalf("cross-connector binding consumed Run IDs: %d", runIDCalls)
	}
}

func TestActionsAreClosedUnsupportedAndDoNotTouchStore(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	runIDCalls := 0
	service, err := NewWithRunIDSource(validEndpoint(), 30*time.Second, store, func() (string, error) {
		runIDCalls++
		return "run_unused", nil
	})
	if err != nil {
		t.Fatalf("NewWithRunIDSource: %v", err)
	}

	tests := []connectorwire.InboundActionV1{
		{Type: connectorwire.ActionStatus},
		{Type: connectorwire.ActionCancel},
		{Type: connectorwire.ActionSelectTarget, TargetAlias: "default"},
	}
	for _, action := range tests {
		t.Run(string(action.Type), func(t *testing.T) {
			event := validTextEvent()
			event.Content = connectorwire.InboundContentV1{
				Type:   connectorwire.ContentTypeAction,
				Action: &action,
			}
			_, err := service.Ingest(context.Background(), event)
			requireServiceErrorCode(t, err, connectorhttp.ErrorActionUnsupported)
		})
	}
	if got := len(store.ingestInputs); got != 0 {
		t.Fatalf("actions reached store %d times", got)
	}
	if runIDCalls != 0 {
		t.Fatalf("actions consumed %d Run IDs", runIDCalls)
	}
}

func TestIngestDedupeConflictAndExactBinding(t *testing.T) {
	t.Parallel()
	type record struct {
		hash  corestore.PayloadHash
		runID string
	}
	records := make(map[string]record)
	store := &fakeStore{}
	store.ingestFn = func(
		_ context.Context,
		input corestore.IngestTextRunInput,
		authorize corestore.TextRunAuthorizer,
		newRunID corestore.RunIDSource,
	) (corestore.IngestResult, error) {
		key := input.ConnectorID + "\x00" + input.EventID
		if existing, ok := records[key]; ok {
			if existing.hash != input.PayloadHash {
				return corestore.IngestResult{}, corestore.ErrConflict
			}
			return corestore.IngestResult{
				Run:       corestore.Run{ID: existing.runID},
				Duplicate: true,
			}, nil
		}
		authorization, err := authorize()
		if err != nil {
			return corestore.IngestResult{}, err
		}
		runID, err := newRunID()
		if err != nil {
			return corestore.IngestResult{}, err
		}
		store.authorizations = append(store.authorizations, authorization)
		store.ingestRunIDs = append(store.ingestRunIDs, runID)
		records[key] = record{hash: input.PayloadHash, runID: runID}
		return corestore.IngestResult{Run: corestore.Run{ID: runID}}, nil
	}
	service := newTestService(t, validEndpoint(), store)
	event := validTextEvent()

	first, err := service.Ingest(context.Background(), event)
	if err != nil {
		t.Fatalf("first Ingest: %v", err)
	}
	second, err := service.Ingest(context.Background(), event)
	if err != nil {
		t.Fatalf("duplicate Ingest: %v", err)
	}
	if first.Disposition != connectorwire.InboundAccepted || second.Disposition != connectorwire.InboundDuplicate {
		t.Fatalf("dispositions = %q, %q", first.Disposition, second.Disposition)
	}
	if first.RunID != "run_test_1" || second.RunID != first.RunID {
		t.Fatalf("durable Run IDs = %q, %q", first.RunID, second.RunID)
	}
	if got := len(store.ingestInputs); got != 2 {
		t.Fatalf("ingest calls = %d, want 2", got)
	}
	firstInput := store.ingestInputs[0]
	secondInput := store.ingestInputs[1]
	if len(store.ingestRunIDs) != 1 {
		t.Fatalf("exact replay consumed Run IDs: %v", store.ingestRunIDs)
	}
	if firstInput.PayloadHash != secondInput.PayloadHash {
		t.Fatal("identical normalized events produced different hashes")
	}
	if len(store.authorizations) != 1 || store.authorizations[0].TargetID != "codex" ||
		store.authorizations[0].TargetRevision != "codex-2026-08" {
		t.Fatalf("exact binding = %#v", store.authorizations)
	}
	if firstInput.OccurredAtUnixMS != event.OccurredAtUnixMS || firstInput.Text != event.Content.Text {
		t.Fatalf("normalized input was not preserved: %#v", firstInput)
	}

	changed := event
	changed.Content.Text = "changed payload under the same event ID"
	_, err = service.Ingest(context.Background(), changed)
	requireServiceErrorCode(t, err, connectorhttp.ErrorEventConflict)
	if store.ingestInputs[2].PayloadHash == firstInput.PayloadHash {
		t.Fatal("changed normalized payload produced the same hash")
	}
}

func TestInboundHashIsCanonicalAndLengthFramed(t *testing.T) {
	t.Parallel()
	event := validTextEvent()
	copyOfEvent := event
	if got, want := hashInboundEvent("discord-main", copyOfEvent), hashInboundEvent("discord-main", event); got != want {
		t.Fatalf("equal typed events hash differently: %x != %x", got, want)
	}

	// These pairs have the same concatenated bytes if field boundaries are not
	// encoded. Length framing must nevertheless keep them distinct.
	left := event
	left.EventID = "ab"
	left.ActorRef = "c"
	right := event
	right.EventID = "a"
	right.ActorRef = "bc"
	if hashInboundEvent("discord-main", left) == hashInboundEvent("discord-main", right) {
		t.Fatal("field-boundary ambiguity in inbound hash")
	}

	changes := []func(*connectorwire.InboundEventV1){
		func(value *connectorwire.InboundEventV1) { value.EventID += "x" },
		func(value *connectorwire.InboundEventV1) { value.ActorRef += "x" },
		func(value *connectorwire.InboundEventV1) { value.ConversationRef += "x" },
		func(value *connectorwire.InboundEventV1) { value.MessageRef += "x" },
		func(value *connectorwire.InboundEventV1) { value.OccurredAtUnixMS++ },
		func(value *connectorwire.InboundEventV1) { value.Content.Text += "x" },
	}
	original := hashInboundEvent("discord-main", event)
	for index, change := range changes {
		changed := event
		change(&changed)
		if hashInboundEvent("discord-main", changed) == original {
			t.Fatalf("semantic field change %d did not affect hash", index)
		}
	}
	if hashInboundEvent("discord-other", event) == original {
		t.Fatal("endpoint-bound Connector identity did not affect hash")
	}
}

func TestRunIDEntropyFailureIsUnavailableAndSkipsStore(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	secret := errors.New("entropy device detail that must stay local")
	service, err := NewWithRunIDSource(validEndpoint(), 30*time.Second, store, func() (string, error) {
		return "", secret
	})
	if err != nil {
		t.Fatalf("NewWithRunIDSource: %v", err)
	}
	_, err = service.Ingest(context.Background(), validTextEvent())
	serviceError := requireServiceErrorCode(t, err, connectorhttp.ErrorUnavailable)
	if strings.Contains(serviceError.Error(), secret.Error()) {
		t.Fatal("closed service error leaked entropy failure")
	}
	if got := len(store.ingestInputs); got != 1 {
		t.Fatalf("replay boundary calls after entropy failure = %d, want 1", got)
	}
}

func TestBoundConnectorIdentityIsUsedForEveryStoreOperation(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	service := newTestService(t, validEndpoint(), store)
	if _, err := service.Ingest(context.Background(), validTextEvent()); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if _, err := service.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 3}); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	completion := connectorwire.DeliveryCompleteV1{
		DeliveryID:         "delivery_1",
		LeaseToken:         "lease_token_1",
		Outcome:            connectorwire.DeliveryDelivered,
		ProviderMessageRef: "discord:message:500",
	}
	if err := service.Complete(context.Background(), completion); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if got := store.ingestInputs[0].ConnectorID; got != "discord-main" {
		t.Fatalf("ingest connector = %q", got)
	}
	if got := store.claimInputs[0].connectorID; got != "discord-main" {
		t.Fatalf("claim connector = %q", got)
	}
	if got := store.completeInputs[0].ConnectorID; got != "discord-main" {
		t.Fatalf("complete connector = %q", got)
	}
}

func TestClaimEmptyAndLeasedDeliveryConversion(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	service := newTestService(t, validEndpoint(), store)

	empty, err := service.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 4})
	if err != nil {
		t.Fatalf("empty Claim: %v", err)
	}
	if empty.Deliveries == nil || len(empty.Deliveries) != 0 {
		t.Fatalf("empty deliveries = %#v, want non-nil empty slice", empty.Deliveries)
	}
	if got, want := store.claimInputs[0], (claimCall{connectorID: "discord-main", limit: 4, lease: 45 * time.Second}); got != want {
		t.Fatalf("claim input = %#v, want %#v", got, want)
	}

	expires := time.Unix(1_800_000_010, 987_000_000).UTC()
	store.claimFn = func(context.Context, string, int, time.Duration) ([]corestore.TextDelivery, error) {
		return []corestore.TextDelivery{
			{
				ID:              "delivery_1",
				RunID:           "run_1",
				ConnectorID:     "discord-main",
				ConversationRef: "discord:channel:200",
				ReplyToRef:      "discord:message:400",
				Text:            "agent output",
				State:           corestore.DeliveryLeased,
				LeaseToken:      "lease_capability_1",
				LeaseExpiresAt:  expires,
			},
		}, nil
	}
	claimed, err := service.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1})
	if err != nil {
		t.Fatalf("leased Claim: %v", err)
	}
	want := connectorwire.OutboundTextV1{
		DeliveryID:         "delivery_1",
		LeaseToken:         "lease_capability_1",
		LeaseExpiresUnixMS: expires.UnixMilli(),
		ConversationRef:    "discord:channel:200",
		ReplyToRef:         "discord:message:400",
		Content: connectorwire.PlainTextV1{
			MediaType: "text/plain",
			Text:      "agent output",
		},
	}
	if len(claimed.Deliveries) != 1 || !reflect.DeepEqual(claimed.Deliveries[0], want) {
		t.Fatalf("claimed deliveries = %#v, want %#v", claimed.Deliveries, want)
	}
}

func TestClaimRejectsBrokenStoreResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		deliveries []corestore.TextDelivery
		limit      int
	}{
		{
			name: "wrong connector",
			deliveries: []corestore.TextDelivery{
				validLeasedDelivery("other-connector"),
			},
			limit: 1,
		},
		{
			name: "not leased",
			deliveries: []corestore.TextDelivery{
				func() corestore.TextDelivery {
					delivery := validLeasedDelivery("discord-main")
					delivery.State = corestore.DeliveryPending
					return delivery
				}(),
			},
			limit: 1,
		},
		{
			name: "store exceeds limit",
			deliveries: []corestore.TextDelivery{
				validLeasedDelivery("discord-main"),
				validLeasedDelivery("discord-main"),
			},
			limit: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{claimFn: func(context.Context, string, int, time.Duration) ([]corestore.TextDelivery, error) {
				return test.deliveries, nil
			}}
			service := newTestService(t, validEndpoint(), store)
			_, err := service.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: test.limit})
			requireServiceErrorCode(t, err, connectorhttp.ErrorInternal)
		})
	}
}

func validLeasedDelivery(connectorID string) corestore.TextDelivery {
	return corestore.TextDelivery{
		ID:              "delivery_1",
		ConnectorID:     connectorID,
		ConversationRef: "discord:channel:200",
		Text:            "output",
		State:           corestore.DeliveryLeased,
		LeaseToken:      "lease_1",
		LeaseExpiresAt:  time.Unix(1_800_000_000, 0).UTC(),
	}
}

func TestCompleteMapsEveryOutcomeAndFailureClass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		wireOutcome connectorwire.DeliveryOutcome
		wireFailure connectorwire.DeliveryFailureClass
		providerRef string
		wantOutcome corestore.DeliveryOutcome
		wantFailure corestore.DeliveryFailureCode
	}{
		{
			name:        "delivered",
			wireOutcome: connectorwire.DeliveryDelivered,
			providerRef: "discord:message:500",
			wantOutcome: corestore.DeliveryOutcomeDelivered,
		},
		{
			name: "retry temporary", wireOutcome: connectorwire.DeliveryRetry,
			wireFailure: connectorwire.FailureTemporary, wantOutcome: corestore.DeliveryOutcomeRetry,
			wantFailure: corestore.DeliveryFailureTemporary,
		},
		{
			name: "retry rate limited", wireOutcome: connectorwire.DeliveryRetry,
			wireFailure: connectorwire.FailureRateLimited, wantOutcome: corestore.DeliveryOutcomeRetry,
			wantFailure: corestore.DeliveryFailureRateLimited,
		},
		{
			name: "retry connector internal", wireOutcome: connectorwire.DeliveryRetry,
			wireFailure: connectorwire.FailureConnectorInternal, wantOutcome: corestore.DeliveryOutcomeRetry,
			wantFailure: corestore.DeliveryFailureConnectorInternal,
		},
		{
			name: "permanent recipient unavailable", wireOutcome: connectorwire.DeliveryPermanentFailure,
			wireFailure: connectorwire.FailureRecipientUnavailable, wantOutcome: corestore.DeliveryOutcomePermanentFailure,
			wantFailure: corestore.DeliveryFailureRecipientUnavailable,
		},
		{
			name: "permanent content rejected", wireOutcome: connectorwire.DeliveryPermanentFailure,
			wireFailure: connectorwire.FailureContentRejected, wantOutcome: corestore.DeliveryOutcomePermanentFailure,
			wantFailure: corestore.DeliveryFailureContentRejected,
		},
		{
			name: "permanent unauthorized", wireOutcome: connectorwire.DeliveryPermanentFailure,
			wireFailure: connectorwire.FailureNotAuthorized, wantOutcome: corestore.DeliveryOutcomePermanentFailure,
			wantFailure: corestore.DeliveryFailureNotAuthorized,
		},
		{
			name: "permanent connector internal", wireOutcome: connectorwire.DeliveryPermanentFailure,
			wireFailure: connectorwire.FailureConnectorInternal, wantOutcome: corestore.DeliveryOutcomePermanentFailure,
			wantFailure: corestore.DeliveryFailureConnectorInternal,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{}
			service := newTestService(t, validEndpoint(), store)
			completion := connectorwire.DeliveryCompleteV1{
				DeliveryID:         "delivery_17",
				LeaseToken:         "lease_capability_17",
				Outcome:            test.wireOutcome,
				ProviderMessageRef: test.providerRef,
				FailureClass:       test.wireFailure,
			}
			if err := service.Complete(context.Background(), completion); err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if got := len(store.completeInputs); got != 1 {
				t.Fatalf("completion calls = %d, want 1", got)
			}
			got := store.completeInputs[0]
			want := corestore.CompleteDeliveryInput{
				ConnectorID:        "discord-main",
				DeliveryID:         "delivery_17",
				LeaseToken:         "lease_capability_17",
				Outcome:            test.wantOutcome,
				ProviderMessageRef: test.providerRef,
				FailureCode:        test.wantFailure,
			}
			if got != want {
				t.Fatalf("completion input = %#v, want %#v", got, want)
			}
		})
	}
}

func TestCompleteMapsStoreErrorsByOperation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		code connectorhttp.ErrorCode
	}{
		{name: "lease lost", err: corestore.ErrLeaseLost, code: connectorhttp.ErrorLeaseLost},
		{name: "not found", err: corestore.ErrNotFound, code: connectorhttp.ErrorDeliveryNotFound},
		{name: "conflicting repeat", err: corestore.ErrConflict, code: connectorhttp.ErrorLeaseLost},
		{name: "invalid store transition", err: corestore.ErrInvalidTransition, code: connectorhttp.ErrorInternal},
		{name: "invalid service input to store", err: corestore.ErrInvalid, code: connectorhttp.ErrorInternal},
		{name: "database unavailable", err: errors.New("database detail"), code: connectorhttp.ErrorUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{completeFn: func(context.Context, corestore.CompleteDeliveryInput) error {
				return fmt.Errorf("wrapped: %w", test.err)
			}}
			service := newTestService(t, validEndpoint(), store)
			err := service.Complete(context.Background(), connectorwire.DeliveryCompleteV1{
				DeliveryID:         "delivery_1",
				LeaseToken:         "lease_1",
				Outcome:            connectorwire.DeliveryDelivered,
				ProviderMessageRef: "discord:message:500",
			})
			requireServiceErrorCode(t, err, test.code)
		})
	}
}

func TestOtherStoreErrorMappingsAreClosed(t *testing.T) {
	t.Parallel()
	t.Run("ingest conflict", func(t *testing.T) {
		store := &fakeStore{ingestFn: func(context.Context, corestore.IngestTextRunInput, corestore.TextRunAuthorizer, corestore.RunIDSource) (corestore.IngestResult, error) {
			return corestore.IngestResult{}, fmt.Errorf("private payload: %w", corestore.ErrConflict)
		}}
		service := newTestService(t, validEndpoint(), store)
		_, err := service.Ingest(context.Background(), validTextEvent())
		requireServiceErrorCode(t, err, connectorhttp.ErrorEventConflict)
	})
	t.Run("ingest invalid", func(t *testing.T) {
		store := &fakeStore{ingestFn: func(context.Context, corestore.IngestTextRunInput, corestore.TextRunAuthorizer, corestore.RunIDSource) (corestore.IngestResult, error) {
			return corestore.IngestResult{}, corestore.ErrInvalid
		}}
		service := newTestService(t, validEndpoint(), store)
		_, err := service.Ingest(context.Background(), validTextEvent())
		requireServiceErrorCode(t, err, connectorhttp.ErrorInternal)
	})
	for _, test := range []struct {
		name string
		err  error
		code connectorhttp.ErrorCode
	}{
		{"ingest expired", corestore.ErrEventExpired, connectorhttp.ErrorEventExpired},
		{"ingest quota", corestore.ErrQuotaExceeded, connectorhttp.ErrorQuotaExceeded},
		{"run in progress", corestore.ErrSessionScopeBusy, connectorhttp.ErrorRunInProgress},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{ingestFn: func(context.Context, corestore.IngestTextRunInput, corestore.TextRunAuthorizer, corestore.RunIDSource) (corestore.IngestResult, error) {
				return corestore.IngestResult{}, test.err
			}}
			service := newTestService(t, validEndpoint(), store)
			_, err := service.Ingest(context.Background(), validTextEvent())
			requireServiceErrorCode(t, err, test.code)
		})
	}
	t.Run("claim unavailable cause is not rendered", func(t *testing.T) {
		private := errors.New("sqlite path and private detail")
		store := &fakeStore{claimFn: func(context.Context, string, int, time.Duration) ([]corestore.TextDelivery, error) {
			return nil, private
		}}
		service := newTestService(t, validEndpoint(), store)
		_, err := service.Claim(context.Background(), connectorwire.DeliveryClaimV1{Limit: 1})
		serviceError := requireServiceErrorCode(t, err, connectorhttp.ErrorUnavailable)
		if strings.Contains(serviceError.Error(), private.Error()) {
			t.Fatal("closed claim error leaked store cause")
		}
	})
}

func TestConstructorRejectsInvalidDependencies(t *testing.T) {
	t.Parallel()
	valid := validEndpoint()
	var typedNilStore *fakeStore
	tests := []struct {
		name     string
		endpoint agentpolicy.Endpoint
		lease    time.Duration
		store    Store
	}{
		{name: "nil store", endpoint: valid, lease: time.Second, store: nil},
		{name: "typed nil store", endpoint: valid, lease: time.Second, store: typedNilStore},
		{name: "short lease", endpoint: valid, lease: time.Second - 1, store: &fakeStore{}},
		{name: "long lease", endpoint: valid, lease: 10*time.Minute + 1, store: &fakeStore{}},
		{name: "zero endpoint", endpoint: agentpolicy.Endpoint{}, lease: time.Second, store: &fakeStore{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.endpoint, test.lease, test.store); err == nil {
				t.Fatal("New accepted invalid dependency")
			}
		})
	}
	if _, err := NewWithRunIDSource(valid, time.Second, &fakeStore{}, nil); err == nil {
		t.Fatal("NewWithRunIDSource accepted nil source")
	}
}

func TestDirectInvalidWireValuesAreClosedInternalErrors(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	service := newTestService(t, validEndpoint(), store)

	_, err := service.Ingest(context.Background(), connectorwire.InboundEventV1{})
	requireServiceErrorCode(t, err, connectorhttp.ErrorInternal)
	_, err = service.Claim(context.Background(), connectorwire.DeliveryClaimV1{})
	requireServiceErrorCode(t, err, connectorhttp.ErrorInternal)
	err = service.Complete(context.Background(), connectorwire.DeliveryCompleteV1{})
	requireServiceErrorCode(t, err, connectorhttp.ErrorInternal)
	if len(store.ingestInputs) != 0 || len(store.claimInputs) != 0 || len(store.completeInputs) != 0 {
		t.Fatal("invalid direct wire values reached the store")
	}
}
