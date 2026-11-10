package daemon

import (
	"net"
	"sync"
)

// connSet tracks live socket connections so shutdown can force-close them,
// unblocking any goroutine parked in a Read() that ctx cancellation alone
// can't interrupt.
type connSet struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (s *connSet) add(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[c] = struct{}{}
}

func (s *connSet) remove(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

func (s *connSet) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}
