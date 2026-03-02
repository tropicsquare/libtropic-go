package libtropic

import "log/slog"

// Option configures a Device.
type Option func(*Device)

// WithLogger sets the logger used by the device.
// Pass slog.New(slog.NewTextHandler(io.Discard, nil)) to silence all output.
func WithLogger(l *slog.Logger) Option {
	return func(d *Device) { d.logger = l }
}

// WithTimeout sets the L1 polling timeout in milliseconds.
// Default: l1TimeoutMSDefault (70 ms).
func WithTimeout(ms uint32) Option {
	return func(d *Device) { d.timeoutMS = ms }
}
