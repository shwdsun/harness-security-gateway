package dockerruntime

import (
	"context"

	"github.com/shwdsun/harness-security-gateway/internal/strictjson"
)

const (
	// Docker's Go template emits exactly one JSON value. Keeping this narrower
	// than the general command output ceiling makes the daemon fact a small,
	// closed protocol rather than accepting the open-ended `docker info` body.
	rootlessInfoFormat   = `{{json .SecurityOptions}}`
	rootlessInfoMaxBytes = 4 << 10
	rootlessInfoMaxDepth = 2
	rootlessOption       = "name=rootless"
	maxSecurityOptions   = 32
)

// attestRootless asks the explicitly configured endpoint for the daemon fact
// immediately before Create. It never consults the ambient Docker context.
func (r *Runtime) attestRootless(ctx context.Context) error {
	output, err := r.run(ctx, "attest-rootless", "info", "--format", rootlessInfoFormat)
	if err != nil {
		return err
	}
	return parseRootlessInfo(output)
}

func parseRootlessInfo(output []byte) error {
	var options []string
	if err := strictjson.Decode(output, rootlessInfoMaxBytes, rootlessInfoMaxDepth, &options); err != nil {
		return ErrInvalidResponse
	}
	if options == nil || len(options) == 0 || len(options) > maxSecurityOptions {
		return ErrInvalidResponse
	}
	rootlessCount := 0
	for _, option := range options {
		if option == rootlessOption {
			rootlessCount++
		}
	}
	if rootlessCount == 0 {
		return ErrRootlessRequired
	}
	if rootlessCount != 1 {
		return ErrInvalidResponse
	}
	return nil
}
