package tropic01

import "log/slog"

// tr01Attrs holds firmware-version-specific attributes detected at Init time.
type tr01Attrs struct {
	fwVersion [4]byte
}

// Device is a TROPIC01 secure element driver.
// Use NewDevice to construct one.
type Device struct {
	t         Transport
	l2buf     [l1LenMax]byte
	session   sessionState
	attrs     tr01Attrs
	logger    *slog.Logger
	timeoutMS uint32
}

// NewDevice creates a Device using the given transport and options.
// Call Init before issuing any commands.
func NewDevice(t Transport, opts ...Option) *Device {
	d := &Device{
		t:         t,
		logger:    slog.Default(),
		timeoutMS: l1TimeoutMSDefault,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Init initialises the transport and reads device attributes.
// It mirrors lt_init in the C library.
func (d *Device) Init() error {
	if err := d.t.Init(); err != nil {
		return err
	}
	d.logger.Debug("device initialised")
	return nil
}

// Deinit releases transport resources and invalidates any active session.
func (d *Device) Deinit() error {
	d.session = sessionState{}
	return d.t.Deinit()
}
