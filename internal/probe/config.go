package probe

import (
	"fmt"
	"unsafe"
)

const maxEnvPrefixLength = int(unsafe.Sizeof(bpfEnvPrefixT{}.Prefix))

func (p *Probe) setEnvPrefixFilter() error {
	m, ok := p.c.Maps[envPrefixMapName]
	if !ok {
		return fmt.Errorf("map %s not found", envPrefixMapName)
	}

	prefix := p.envPrefixFilter

	if len(prefix) > maxEnvPrefixLength {
		return fmt.Errorf("env prefix filter is too long: provide length is %d, max allowed length is %d", len(prefix), maxEnvPrefixLength)
	}

	key := uint32(0)
	value := bpfEnvPrefixT{Len: uint64(len(prefix))}
	copy(value.Prefix[:], prefix)

	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("can't put env prefix in map: %w", err)
	}
	return nil
}

const maxOpenFilenameLength = int(unsafe.Sizeof(bpfOpenFilenameT{}.Buf))

func (p *Probe) setFilenamesToTrackWhenOpened() error {
	m, ok := p.c.Maps[openTrackingFilenameMapName]
	if !ok {
		return fmt.Errorf("map %s not found", openTrackingFilenameMapName)
	}

	if len(p.openFilesToTrack) > int(m.MaxEntries()) {
		return fmt.Errorf("too many files to track for open: provided %d, max allowed %d", len(p.openFilesToTrack), m.MaxEntries())
	}

	for i, filename := range p.openFilesToTrack {
		if len(filename) > maxOpenFilenameLength {
			return fmt.Errorf("filename is too long: provide length is %d, max allowed length is %d", len(filename), maxOpenFilenameLength)
		}

		key := uint32(i)
		value := bpfOpenFilenameT{Len: uint64(len(filename))}
		copy(value.Buf[:], filename)

		if err := m.Put(key, value); err != nil {
			return fmt.Errorf("can't put filename in map: %w", err)
		}
	}
	return nil
}

const maxExecFileToIgnoreLen = int(unsafe.Sizeof(bpfExecFilenameT{}.Buf))

func (p *Probe) setExecFilenamesToIgnore() error {
	m, ok := p.c.Maps[execFilesToFilterMapName]
	if !ok {
		return fmt.Errorf("map %s not found", execFilesToFilterMapName)
	}

	if len(p.execFilesToFilter) > int(m.MaxEntries()) {
		return fmt.Errorf("too many executable files to ignore: provided %d, max allowed %d", len(p.execFilesToFilter), m.MaxEntries())
	}

	key := uint32(0)
	for filename := range p.execFilesToFilter {
		if len(filename) > maxExecFileToIgnoreLen {
			return fmt.Errorf("executable filename is too long: provide length is %d, max allowed length is %d", len(filename), maxExecFileToIgnoreLen)
		}

		value := bpfExecFilenameT{Len: uint64(len(filename))}
		copy(value.Buf[:], filename)

		if err := m.Put(key, value); err != nil {
			return fmt.Errorf("can't put filename in map: %w", err)
		}
		key++
	}
	return nil
}
