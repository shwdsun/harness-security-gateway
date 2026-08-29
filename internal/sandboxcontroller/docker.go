package sandboxcontroller

import (
	"context"
	"errors"
	"io"

	"github.com/shwdsun/harness-security-gateway/internal/dockerruntime"
	"github.com/shwdsun/harness-security-gateway/internal/targetmanifest"
)

// DockerRuntime adapts the concrete, policy-locked Docker boundary to the
// consumer-owned Runtime interface used by the lifecycle controller.
type DockerRuntime struct {
	runtime *dockerruntime.Runtime
}

func NewDockerRuntime(runtime *dockerruntime.Runtime) (*DockerRuntime, error) {
	if runtime == nil {
		return nil, errors.New("sandboxcontroller: nil Docker runtime")
	}
	return &DockerRuntime{runtime: runtime}, nil
}

func (r *DockerRuntime) ListManaged(ctx context.Context) ([]string, error) {
	refs, err := r.runtime.ListManaged(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(refs))
	for index, ref := range refs {
		result[index] = ref.String()
	}
	return result, nil
}

func (r *DockerRuntime) Create(ctx context.Context, runID string, manifest targetmanifest.Manifest) (string, error) {
	ref, err := r.runtime.Create(ctx, runID, manifest)
	return ref.String(), err
}

func (r *DockerRuntime) LookupIntent(
	ctx context.Context,
	runID string,
	manifest targetmanifest.Manifest,
) (string, bool, error) {
	ref, found, err := r.runtime.LookupIntent(ctx, runID, manifest)
	return ref.String(), found, err
}

func (r *DockerRuntime) AttachStart(ctx context.Context, value string) (Process, error) {
	ref, err := dockerruntime.ParseContainerRef(value)
	if err != nil {
		return nil, err
	}
	process, err := r.runtime.AttachStart(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &dockerProcess{process: process}, nil
}

func (r *DockerRuntime) Inspect(ctx context.Context, value string) (dockerruntime.Inspection, error) {
	ref, err := dockerruntime.ParseContainerRef(value)
	if err != nil {
		return dockerruntime.Inspection{}, err
	}
	return r.runtime.Inspect(ctx, ref)
}

func (r *DockerRuntime) Stop(ctx context.Context, value string) error {
	ref, err := dockerruntime.ParseContainerRef(value)
	if err != nil {
		return err
	}
	return r.runtime.Stop(ctx, ref)
}

func (r *DockerRuntime) Kill(ctx context.Context, value string) error {
	ref, err := dockerruntime.ParseContainerRef(value)
	if err != nil {
		return err
	}
	return r.runtime.Kill(ctx, ref)
}

func (r *DockerRuntime) RemoveStopped(ctx context.Context, value string) error {
	ref, err := dockerruntime.ParseContainerRef(value)
	if err != nil {
		return err
	}
	return r.runtime.RemoveStopped(ctx, ref)
}

type dockerProcess struct {
	process *dockerruntime.Process
}

func (p *dockerProcess) Input() io.WriteCloser      { return p.process.Stdin }
func (p *dockerProcess) Output() io.ReadCloser      { return p.process.Stdout }
func (p *dockerProcess) Diagnostics() io.ReadCloser { return p.process.Stderr }
func (p *dockerProcess) Wait() error                { return p.process.Wait() }

var _ Runtime = (*DockerRuntime)(nil)
var _ Process = (*dockerProcess)(nil)
