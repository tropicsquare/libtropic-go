// Package sim provides a TROPIC01 Transport simulator for use in tests.
//
// Two modes are available:
//   - Queued: pre-load raw frame bytes; each Transfer copies from the queue.
//   - Stateful: maintains in-memory chip state and processes commands (future).
package sim

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Sim implements [libtropic.Transport] for testing without physical hardware.
type Sim struct {
	mu         sync.Mutex
	queue      [][]byte // pending MISO frames (queued mode)
	inProgress bool     // true between CSNLow and CSNHigh
}

// NewQueued returns a Sim in queued-response mode.
func NewQueued() *Sim {
	return &Sim{}
}

// EnqueueResponse pre-loads a MISO frame that will be returned on the next Transfer.
func (s *Sim) EnqueueResponse(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	s.queue = append(s.queue, cp)
}

// Init implements Transport.
func (s *Sim) Init() error { return nil }

// Deinit implements Transport.
func (s *Sim) Deinit() error { return nil }

// CSNLow implements Transport.
func (s *Sim) CSNLow() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inProgress {
		return errors.New("sim: CSNLow called while transaction in progress")
	}
	s.inProgress = true
	return nil
}

// CSNHigh implements Transport and advances the response queue.
func (s *Sim) CSNHigh() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.inProgress {
		return errors.New("sim: CSNHigh called without CSNLow")
	}
	s.inProgress = false
	if len(s.queue) > 0 {
		s.queue = s.queue[1:]
	}
	return nil
}

// Transfer implements Transport. In queued mode it copies the head of the
// response queue into buf (zero-padding if the response is shorter).
func (s *Sim) Transfer(buf []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.inProgress {
		return errors.New("sim: Transfer called without CSNLow")
	}
	if len(s.queue) == 0 {
		return fmt.Errorf("sim: Transfer called with empty queue")
	}
	resp := s.queue[0]
	n := copy(buf, resp)
	for i := n; i < len(buf); i++ {
		buf[i] = 0
	}
	return nil
}

// Delay implements Transport.
func (s *Sim) Delay(ms uint32) error {
	time.Sleep(time.Duration(ms) * time.Millisecond)
	return nil
}

// RandomBytes implements Transport using a simple counter for determinism in tests.
func (s *Sim) RandomBytes(buf []byte) error {
	for i := range buf {
		buf[i] = byte(i & 0xff)
	}
	return nil
}
