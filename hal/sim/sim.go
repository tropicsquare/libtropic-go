// Package sim provides a TROPIC01 Transport simulator for use in tests.
//
// Two modes are available:
//   - Queued: pre-load raw frame bytes; each Transfer copies from the queue.
//   - Stateful: maintains in-memory chip state and processes commands (skeleton).
package sim

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// simMode selects the Transfer behaviour of a Sim.
type simMode int

const (
	modeQueued   simMode = iota // pre-loaded response queue
	modeStateful                // parse request and build RESULT_OK response
)

// stateful tracks per-transaction phase for stateful mode.
//
// Within a single CSN-low/high cycle the L1 layer may issue up to three
// Transfer calls (poll → header → data).  The phase field counts how many
// Transfers have been served in the current transaction.
type stateful struct {
	hasResponse bool   // true once a request has been received
	phase       int    // number of Transfers served in the current transaction
	respData    []byte // pre-built response body: STATUS + LEN + DATA + CRC_HI + CRC_LO
}

// Sim implements [libtropic.Transport] for testing without physical hardware.
type Sim struct {
	mu         sync.Mutex
	queue      [][]byte // pending MISO frames (queued mode)
	inProgress bool     // true between CSNLow and CSNHigh
	mode       simMode
	sf         stateful // used only in modeStateful
}

// NewQueued returns a Sim in queued-response mode.
func NewQueued() *Sim {
	return &Sim{mode: modeQueued}
}

// NewStateful returns a Sim in stateful mode.
//
// The stateful sim parses each incoming L2 request frame and returns a
// well-formed RESULT_OK response with empty data.  This is sufficient for
// exercising the L1/L2 framing layers without a physical chip.
func NewStateful() *Sim {
	return &Sim{mode: modeStateful}
}

// crc16 computes the CRC-16/IBM checksum matching the libtropic protocol.
// Algorithm: polynomial 0x8005, init 0x0000, MSB-first, final byte-swap.
// This mirrors the crc16 function in the parent libtropic package.
func crc16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x8005
			} else {
				crc <<= 1
			}
		}
	}
	return crc<<8 | crc>>8
}

// buildResultOK constructs the response bytes for a zero-data RESULT_OK frame:
//
//	STATUS (0x02) | LEN (0x00) | CRC_HI | CRC_LO
func buildResultOK() []byte {
	const status = 0x02 // l2StatusResultOK
	const dataLen = 0x00
	crc := crc16([]byte{status, dataLen})
	return []byte{status, dataLen, byte(crc >> 8), byte(crc)}
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
	if s.mode == modeStateful {
		s.sf.phase = 0 // reset per-transaction phase counter
	}
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
// In stateful mode it parses the incoming request and returns a RESULT_OK
// response split across up to three calls per L1 read cycle:
//
//  1. Phase 0 — write: receive the request frame; no bytes returned.
//  2. Phase 0 — poll (next CSN transaction): return chip_status=0x01 (READY).
//  3. Phase 1 — header: return STATUS=0x02 and LEN=0x00.
//  4. Phase 2 — data+CRC: return the CRC bytes for the empty-data response.
func (s *Sim) Transfer(buf []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.inProgress {
		return errors.New("sim: Transfer called without CSNLow")
	}

	if s.mode == modeStateful {
		return s.transferStateful(buf)
	}

	// Queued mode.
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

// transferStateful handles Transfer calls for modeStateful.
// Must be called with s.mu held.
//
// The L1 layer performs transfers in this order:
//
//	Write transaction:  CSNLow → Transfer(request)                    → CSNHigh
//	Read transaction:   CSNLow → Transfer(poll 1B) → Transfer(hdr 2B)
//	                           → Transfer(data+CRC nB)               → CSNHigh
//
// sf.phase is reset to 0 on each CSNLow.  Within the read transaction the
// three successive Transfers map to phases 0, 1, and 2.
//
// To distinguish the write Transfer from the poll Transfer (both arrive at
// phase 0), we use sf.hasResponse: it is false when we are still waiting for
// a request, and true once a request has been absorbed.
func (s *Sim) transferStateful(buf []byte) error {
	if !s.sf.hasResponse {
		// This is the write Transfer: absorb the request and prepare a response.
		// buf contains the outgoing request — we ignore its content for the
		// skeleton and always reply with a zero-data RESULT_OK.
		s.sf.respData = buildResultOK()
		s.sf.hasResponse = true
		// Nothing is returned to the caller (MOSI-only write transaction).
		for i := range buf {
			buf[i] = 0
		}
		return nil
	}

	// Read transaction: serve the response in three phases.
	switch s.sf.phase {
	case 0:
		// Poll: return chip_status = 0x01 (READY) in buf[0].
		if len(buf) < 1 {
			return errors.New("sim: stateful poll Transfer buf too short")
		}
		buf[0] = 0x01 // l1StatusReady
		for i := 1; i < len(buf); i++ {
			buf[i] = 0
		}
		s.sf.phase++
	case 1:
		// Header: return STATUS (buf[0]) and LEN (buf[1]).
		if len(buf) < 2 {
			return errors.New("sim: stateful header Transfer buf too short")
		}
		buf[0] = s.sf.respData[0] // STATUS
		buf[1] = s.sf.respData[1] // LEN
		for i := 2; i < len(buf); i++ {
			buf[i] = 0
		}
		s.sf.phase++
	case 2:
		// Data + CRC: return DATA bytes followed by CRC_HI and CRC_LO.
		// respData layout: [STATUS, LEN, ...DATA, CRC_HI, CRC_LO]
		// The data+CRC portion starts at index 2.
		payload := s.sf.respData[2:]
		n := copy(buf, payload)
		for i := n; i < len(buf); i++ {
			buf[i] = 0
		}
		s.sf.phase++
		// Reset for next command after CSNHigh.
		s.sf.hasResponse = false
	default:
		return fmt.Errorf("sim: stateful Transfer unexpected phase %d", s.sf.phase)
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
