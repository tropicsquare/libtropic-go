package tropic01_test

import (
	"testing"

	tropic01 "libtropic-go/tropic01"
	"libtropic-go/tropic01/hal/sim"
)

func newTestDevice(t *testing.T) *tropic01.Device {
	t.Helper()
	s := sim.NewQueued()
	d := tropic01.NewDevice(s)
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPingNoSession(t *testing.T) {
	d := newTestDevice(t)
	_, err := d.Ping([]byte{0x01, 0x02})
	if err != tropic01.ErrNoSession {
		t.Errorf("Ping without session: got %v, want ErrNoSession", err)
	}
}

func TestSessionStartNoSession(t *testing.T) {
	d := newTestDevice(t)
	// SessionAbort without active session should not panic.
	err := d.SessionAbort()
	// May return error (L2 send fails with empty queue) or nil — must not panic.
	_ = err
}

func TestECCKeyGenerateNoSession(t *testing.T) {
	d := newTestDevice(t)
	err := d.ECCKeyGenerate(0, 0)
	if err != tropic01.ErrNoSession {
		t.Errorf("ECCKeyGenerate without session: got %v, want ErrNoSession", err)
	}
}

func TestRMemDataWriteNoSession(t *testing.T) {
	d := newTestDevice(t)
	err := d.RMemDataWrite(0, []byte{0x01})
	if err != tropic01.ErrNoSession {
		t.Errorf("RMemDataWrite without session: got %v, want ErrNoSession", err)
	}
}

func TestFirmwareUpdateNotImplemented(t *testing.T) {
	d := newTestDevice(t)
	err := d.FirmwareUpdate()
	if err != tropic01.ErrNotImplemented {
		t.Errorf("FirmwareUpdate: got %v, want ErrNotImplemented", err)
	}
}
