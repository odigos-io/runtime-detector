// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package probe

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfEnvPrefixT struct {
	Len    uint64
	Prefix [128]uint8
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	TracepointSchedSchedProcessExit    *ebpf.ProgramSpec `ebpf:"tracepoint__sched__sched_process_exit"`
	TracepointSyscallsSysEnterExecve   *ebpf.ProgramSpec `ebpf:"tracepoint__syscalls__sys_enter_execve"`
	TracepointBtfSchedSchedProcessFork *ebpf.ProgramSpec `ebpf:"tracepoint_btf__sched__sched_process_fork"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	EnvPrefix             *ebpf.MapSpec `ebpf:"env_prefix"`
	Events                *ebpf.MapSpec `ebpf:"events"`
	TrackedPidsToNsPids   *ebpf.MapSpec `ebpf:"tracked_pids_to_ns_pids"`
	UserPidToContainerPid *ebpf.MapSpec `ebpf:"user_pid_to_container_pid"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	EnvPrefix             *ebpf.Map `ebpf:"env_prefix"`
	Events                *ebpf.Map `ebpf:"events"`
	TrackedPidsToNsPids   *ebpf.Map `ebpf:"tracked_pids_to_ns_pids"`
	UserPidToContainerPid *ebpf.Map `ebpf:"user_pid_to_container_pid"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.EnvPrefix,
		m.Events,
		m.TrackedPidsToNsPids,
		m.UserPidToContainerPid,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	TracepointSchedSchedProcessExit    *ebpf.Program `ebpf:"tracepoint__sched__sched_process_exit"`
	TracepointSyscallsSysEnterExecve   *ebpf.Program `ebpf:"tracepoint__syscalls__sys_enter_execve"`
	TracepointBtfSchedSchedProcessFork *ebpf.Program `ebpf:"tracepoint_btf__sched__sched_process_fork"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.TracepointSchedSchedProcessExit,
		p.TracepointSyscallsSysEnterExecve,
		p.TracepointBtfSchedSchedProcessFork,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_arm64_bpfel.o
var _BpfBytes []byte
