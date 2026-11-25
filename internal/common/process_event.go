package common

type EventType uint32

const (
	// These constants must be in sync with the BPF programs.
	Undefined EventType = iota
	EventTypeExec
	EventTypeExit
	EventTypeFork
	EventTypeFileOpen
)

type PIDEvent struct {
	Type EventType
	Pid  int
	// EnvPrefixFound is set for exec events in which eBPF found the env prefix in the environment passed to execve.
	EnvPrefixFound bool
}

func (et EventType) String() string {
	switch et {
	case EventTypeExec:
		return "exec"
	case EventTypeExit:
		return "exit"
	case EventTypeFork:
		return "fork"
	case EventTypeFileOpen:
		return "file_open"
	default:
		return "undefined"
	}
}
