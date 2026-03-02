package sim_test

import (
	"testing"

	"go-libtropic/hal/sim"
)

func TestQueuedTransfer(t *testing.T) {
	s := sim.NewQueued()
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	// Enqueue a 4-byte response
	s.EnqueueResponse([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	buf := make([]byte, 4)
	if err := s.CSNLow(); err != nil {
		t.Fatal(err)
	}
	if err := s.Transfer(buf); err != nil {
		t.Fatal(err)
	}
	if err := s.CSNHigh(); err != nil {
		t.Fatal(err)
	}

	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	for i, b := range want {
		if buf[i] != b {
			t.Errorf("buf[%d] = 0x%02x, want 0x%02x", i, buf[i], b)
		}
	}
}

func TestQueuedTransferEmptyQueue(t *testing.T) {
	s := sim.NewQueued()
	_ = s.Init()
	buf := make([]byte, 4)
	_ = s.CSNLow()
	if err := s.Transfer(buf); err == nil {
		t.Error("expected error on empty queue, got nil")
	}
}
