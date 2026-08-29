MOCK_IMAGE ?= harness-gateway/mock-runner:dev

.PHONY: fmt build test test-race vet mock-image config-check demo-security bakeoff-check

fmt:
	gofmt -w $$(find cmd demo internal -name '*.go' -type f)

build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/agentd ./cmd/agentd
	go build -buildvcs=false -trimpath -o bin/sandboxd ./cmd/sandboxd
	go build -buildvcs=false -trimpath -o bin/hgwctl ./cmd/hgwctl
	go build -buildvcs=false -trimpath -o bin/fake-connector ./cmd/fake-connector

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

mock-image:
	docker build --network=none --provenance=false --tag $(MOCK_IMAGE) --file runners/mock/Dockerfile .
	docker image inspect --format 'RepoDigests={{json .RepoDigests}}' $(MOCK_IMAGE)

config-check:
	jq -e '(.schema == "agentd/v3") and (.bindings | length == 1)' config/agentd.example.json >/dev/null
	jq -e '(.schema == "sandboxd/v2") and (.targets | length == 1) and (.runner_states | length == 1)' config/sandboxd.example.json >/dev/null
	jq -e -s '.[0] as $$agent | .[1] as $$sandbox | ($$agent.bindings[0].target.id == $$sandbox.targets[0].id) and ($$agent.bindings[0].target.revision == $$sandbox.targets[0].revision) and ($$sandbox.targets[0].state_ref == $$sandbox.runner_states[0].ref)' config/agentd.example.json config/sandboxd.example.json >/dev/null

demo-security:
	@go run ./demo/security

bakeoff-check:
	bash -n bakeoff/fixtures/prepare.sh
	jq -e '.schema_version == 1 and (.outcomes == ["PASS", "FAIL", "NOT_SUPPORTED", "NOT_OBSERVABLE", "BLOCKED"]) and (([.cases[].id] | length) == ([.cases[].id] | unique | length)) and all(.cases[]; (.id | test("^[A-Z]+-[0-9]{2}$$")) and (.priority == "P0" or .priority == "P1") and (.title | length > 0) and (.assertion | length > 0))' bakeoff/cases.json >/dev/null
