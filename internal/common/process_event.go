package common

type EventType uint32

const (
	// These constants must be in sync with the BPF programs.
	Undefined EventType = iota
	EventTypeExec
	EventTypeExit
	EventTypeFork
)

type PIDEvent struct {
	Type EventType
	Pid  int
}

func (et EventType) String() string {
	switch et {
	case EventTypeExec:
		return "exec"
	case EventTypeExit:
		return "exit"
	default:
		return "undefined"
	}
}
