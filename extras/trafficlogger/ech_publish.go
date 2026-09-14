package trafficlogger

import "sync"

// ECHPublishState is where publishing the ECH config list to DNS stands.
type ECHPublishState string

const (
	// ECHPublishPending means at least one domain has no finished attempt
	// yet. Publishing runs in the background after the server starts, so an
	// /ech query that lands early sees this.
	ECHPublishPending ECHPublishState = "pending"
	// ECHPublishPublished means the provider accepted the record for every
	// domain.
	ECHPublishPublished ECHPublishState = "published"
	// ECHPublishFailed means at least one domain's attempt ended in an
	// error; the server log has the record and the reason.
	ECHPublishFailed ECHPublishState = "failed"
)

// ECHPublishStatus tracks the outcome of publishing the ECH config list to
// DNS, per domain, so /ech can report it instead of the server log. The
// publisher writes into it from its own goroutine; the API reads it, so every
// access goes through the mutex.
type ECHPublishStatus struct {
	mu      sync.RWMutex
	domains map[string]ECHPublishState
}

// NewECHPublishStatus starts every domain out as pending.
func NewECHPublishStatus(domains []string) *ECHPublishStatus {
	s := &ECHPublishStatus{domains: make(map[string]ECHPublishState, len(domains))}
	for _, d := range domains {
		s.domains[d] = ECHPublishPending
	}
	return s
}

// Published records that the provider accepted the record for domain.
func (s *ECHPublishStatus) Published(domain string) {
	s.set(domain, ECHPublishPublished)
}

// Failed records that publishing for domain ended in an error.
func (s *ECHPublishStatus) Failed(domain string) {
	s.set(domain, ECHPublishFailed)
}

// set replaces domain's state. A domain that was not registered up front is a
// programming error - the publisher and the status are built from the same
// list - so it is a panic rather than a silent insert.
func (s *ECHPublishStatus) set(domain string, state ECHPublishState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.domains[domain]; !ok {
		panic("trafficlogger: ECH publish status update for an unregistered domain " + domain)
	}
	s.domains[domain] = state
}

// State folds the per-domain outcomes into one: failed if any domain failed,
// else pending if any is still pending, else published.
func (s *ECHPublishStatus) State() ECHPublishState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := ECHPublishPublished
	for _, d := range s.domains {
		switch d {
		case ECHPublishFailed:
			return ECHPublishFailed
		case ECHPublishPending:
			state = ECHPublishPending
		}
	}
	return state
}
