package libtropic_test

import (
	"testing"

	libtropic "go-libtropic"
	"go-libtropic/hal/sim"
)

func newTestDevice(t *testing.T) *libtropic.Device {
	t.Helper()
	s := sim.NewQueued()
	d := libtropic.NewDevice(s)
	if err := d.Init(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPingNoSession(t *testing.T) {
	d := newTestDevice(t)
	_, err := d.Ping([]byte{0x01, 0x02})
	if err != libtropic.ErrNoSession {
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
	if err != libtropic.ErrNoSession {
		t.Errorf("ECCKeyGenerate without session: got %v, want ErrNoSession", err)
	}
}

func TestRMemDataWriteNoSession(t *testing.T) {
	d := newTestDevice(t)
	err := d.RMemDataWrite(0, []byte{0x01})
	if err != libtropic.ErrNoSession {
		t.Errorf("RMemDataWrite without session: got %v, want ErrNoSession", err)
	}
}

func TestFirmwareUpdateNotImplemented(t *testing.T) {
	d := newTestDevice(t)
	err := d.FirmwareUpdate()
	if err != libtropic.ErrNotImplemented {
		t.Errorf("FirmwareUpdate: got %v, want ErrNotImplemented", err)
	}
}
