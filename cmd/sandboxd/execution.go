package main

import (
	"github.com/shwdsun/harness-security-gateway/internal/credentialsource"
	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxconfig"
	"github.com/shwdsun/harness-security-gateway/internal/sandboxservice"
)

type executionSetup struct {
	authority sandboxservice.AuthorityResolverFunc
	bindings  []credentialsource.Binding
	runtime   func() (*dockerruntime.Runtime, error)
}

// Resolve native authority before any startup mutation. Mock runtime creation
// stays after durable Runner-state registration and directory creation.
func prepareExecution(config sandboxconfig.Config) (executionSetup, error) {
	if err := config.Validate(); err != nil {
		return executionSetup{}, err
	}
	if config.Schema == sandboxconfig.SchemaCodexV1 {
		return prepareCodex(config)
	}
	return executionSetup{authority: config.ResolveTargetAuthority,
		runtime: func() (*dockerruntime.Runtime, error) { return dockerruntime.New(config) }}, nil
}
