package common

// ProcessesFilter filters processes based on some specific logic.
// Multiple filters can be chained together, each receiving the output of the previous filter.
type ProcessesFilter interface {
	// Add is called when a new process should be inspected by the filter,
	// or after some changes in the process state occurred which the next filter should be aware of.
	Add(pid int, eventType EventType)
	// Remove is called when a process should be removed from the filter.
	// If the process in not tracked by the filter, this method should be a no-op.
	Remove(pid int)
	// Close is called when the filter should release any resources it holds.
	// This method should be idempotent.
	// When filters are chained, each filter should call Close on the next filter in the chain.
	Close() error
}
