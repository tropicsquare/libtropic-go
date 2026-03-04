package tropic01

import (
	"testing"

	"libtropic-go/tropic01/hal/sim"
)

func TestL1Write(t *testing.T) {
	s := sim.NewQueued()
	d := NewDevice(s)
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	// l1Write now retries until chip reports READY.
	// Enqueue a response with the READY bit set in chip status (byte 0).
	resp := make([]byte, 4)
	resp[0] = l1StatusReady
	s.EnqueueResponse(resp)
	d.l2buf[0] = 0xAB
	d.l2buf[1] = 0xCD
	if err := l1Write(d, 2); err != nil {
		t.Errorf("l1Write: %v", err)
	}
}

func TestL1ReadTimeout(t *testing.T) {
	s := sim.NewQueued()
	d := NewDevice(s)
	_ = d.Init()
	// Enqueue l1MaxRetries frames where chip status byte = 0x00 (not ready).
	// l1Read should exhaust retries and return ErrL1Timeout.
	for range l1MaxRetries {
		frame := make([]byte, l1LenMax)
		frame[0] = 0x00 // chip status = not ready
		s.EnqueueResponse(frame)
	}
	err := l1Read(d)
	if err != ErrL1Timeout {
		t.Errorf("l1Read timeout: got %v, want ErrL1Timeout", err)
	}
}
