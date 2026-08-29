// Package agentpolicy compiles the operator configuration into one closed,
// immutable Exact Binding Authorization decision table.
package agentpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/shwdsun/harness-security-gateway/internal/agentconfig"
)

const (
	actionRunCreate          = "run.create"
	bindingFingerprintDomain = "hgw.binding/v1\x00"
	policyRevisionDomain     = "hgw.policy/v1\x00"
)

var (
	ErrInvalid          = errors.New("invalid agent policy")
	ErrUnknownConnector = errors.New("unknown policy connector")
	ErrSelfEvent        = errors.New("connector self event")
	ErrNoBinding        = errors.New("no exact binding")
)

type bindingKey struct {
	actorRef        string
	conversationRef string
}

// Decision is the complete immutable authority returned for one run.create.
// Binding labels are deliberately absent because they do not grant authority.
type Decision struct {
	BindingFingerprint string
	PolicyRevision     string
	TargetID           string
	TargetRevision     string
}

// Endpoint is one Connector-scoped evaluator. Its fields are private and its
// binding map is copied during compilation, so caller config mutation cannot
// widen authority after startup.
type Endpoint struct {
	connectorID    string
	selfActorRef   string
	policyRevision string
	bindings       map[bindingKey]Decision
}

func (e Endpoint) ConnectorID() string { return e.connectorID }

func (e Endpoint) Authorize(actorRef, conversationRef string) (Decision, error) {
	if e.connectorID == "" || e.selfActorRef == "" || e.policyRevision == "" || e.bindings == nil {
		return Decision{}, ErrInvalid
	}
	if actorRef == "" || conversationRef == "" {
		return Decision{}, ErrInvalid
	}
	if actorRef == e.selfActorRef {
		return Decision{}, ErrSelfEvent
	}
	decision, ok := e.bindings[bindingKey{actorRef: actorRef, conversationRef: conversationRef}]
	if !ok {
		return Decision{}, ErrNoBinding
	}
	return decision, nil
}

// Policy is the immutable compiled ingress policy shared by Connector-bound
// services. Endpoint returns another private map copy to keep ownership simple.
type Policy struct {
	revision  string
	endpoints map[string]Endpoint
}

func Compile(config agentconfig.Config) (*Policy, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	revision, err := policyRevision(config)
	if err != nil {
		return nil, err
	}
	policy := &Policy{
		revision:  revision,
		endpoints: make(map[string]Endpoint, len(config.Connectors)),
	}
	for _, connector := range config.Connectors {
		policy.endpoints[connector.ID] = Endpoint{
			connectorID: connector.ID, selfActorRef: connector.SelfActorRef,
			policyRevision: revision, bindings: make(map[bindingKey]Decision),
		}
	}
	for _, binding := range config.Bindings {
		fingerprint, err := bindingFingerprint(binding)
		if err != nil {
			return nil, err
		}
		endpoint := policy.endpoints[binding.ConnectorID]
		key := bindingKey{actorRef: binding.ActorRef, conversationRef: binding.ConversationRef}
		endpoint.bindings[key] = Decision{
			BindingFingerprint: fingerprint,
			PolicyRevision:     revision,
			TargetID:           binding.Target.ID,
			TargetRevision:     binding.Target.Revision,
		}
		policy.endpoints[binding.ConnectorID] = endpoint
	}
	return policy, nil
}

func (p *Policy) Revision() string {
	if p == nil {
		return ""
	}
	return p.revision
}

func (p *Policy) Endpoint(connectorID string) (Endpoint, error) {
	if p == nil || p.revision == "" || p.endpoints == nil {
		return Endpoint{}, ErrInvalid
	}
	endpoint, ok := p.endpoints[connectorID]
	if !ok {
		return Endpoint{}, ErrUnknownConnector
	}
	copyEndpoint := endpoint
	copyEndpoint.bindings = make(map[bindingKey]Decision, len(endpoint.bindings))
	for key, decision := range endpoint.bindings {
		copyEndpoint.bindings[key] = decision
	}
	return copyEndpoint, nil
}

type canonicalBinding struct {
	ConnectorID     string `json:"connector_id"`
	ActorRef        string `json:"actor_ref"`
	ConversationRef string `json:"conversation_ref"`
	Action          string `json:"action"`
	TargetID        string `json:"target_id"`
	TargetRevision  string `json:"target_revision"`
}

func bindingFingerprint(binding agentconfig.Binding) (string, error) {
	encoded, err := json.Marshal(canonicalBinding{
		ConnectorID: binding.ConnectorID, ActorRef: binding.ActorRef,
		ConversationRef: binding.ConversationRef, Action: actionRunCreate,
		TargetID: binding.Target.ID, TargetRevision: binding.Target.Revision,
	})
	if err != nil {
		return "", fmt.Errorf("%w: encode binding fingerprint: %v", ErrInvalid, err)
	}
	return digest(bindingFingerprintDomain, encoded), nil
}

type canonicalConnector struct {
	ConnectorID  string `json:"connector_id"`
	PeerUID      uint32 `json:"peer_uid"`
	SelfActorRef string `json:"self_actor_ref"`
}

type canonicalPolicy struct {
	Schema     string               `json:"schema"`
	Action     string               `json:"action"`
	Connectors []canonicalConnector `json:"connectors"`
	Bindings   []canonicalBinding   `json:"bindings"`
}

func policyRevision(config agentconfig.Config) (string, error) {
	canonical := canonicalPolicy{
		Schema: "agentd-policy/v1", Action: actionRunCreate,
		Connectors: make([]canonicalConnector, 0, len(config.Connectors)),
		Bindings:   make([]canonicalBinding, 0, len(config.Bindings)),
	}
	for _, connector := range config.Connectors {
		canonical.Connectors = append(canonical.Connectors, canonicalConnector{
			ConnectorID: connector.ID, PeerUID: connector.PeerUID.Uint32(),
			SelfActorRef: connector.SelfActorRef,
		})
	}
	for _, binding := range config.Bindings {
		canonical.Bindings = append(canonical.Bindings, canonicalBinding{
			ConnectorID: binding.ConnectorID, ActorRef: binding.ActorRef,
			ConversationRef: binding.ConversationRef, Action: actionRunCreate,
			TargetID: binding.Target.ID, TargetRevision: binding.Target.Revision,
		})
	}
	sort.Slice(canonical.Connectors, func(i, j int) bool {
		return canonical.Connectors[i].ConnectorID < canonical.Connectors[j].ConnectorID
	})
	sort.Slice(canonical.Bindings, func(i, j int) bool {
		left, right := canonical.Bindings[i], canonical.Bindings[j]
		if left.ConnectorID != right.ConnectorID {
			return left.ConnectorID < right.ConnectorID
		}
		if left.ActorRef != right.ActorRef {
			return left.ActorRef < right.ActorRef
		}
		return left.ConversationRef < right.ConversationRef
	})
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("%w: encode policy revision: %v", ErrInvalid, err)
	}
	return digest(policyRevisionDomain, encoded), nil
}

func digest(domain string, encoded []byte) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(domain))
	_, _ = hasher.Write(encoded)
	return hex.EncodeToString(hasher.Sum(nil))
}
