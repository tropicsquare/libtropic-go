package tropic01

// Transport is the hardware abstraction layer for TROPIC01 SPI communication.
//
// Implementations must be safe to call sequentially; concurrent access is
// the caller's responsibility.
//
// See hal/linux for a Linux spidev+GPIO implementation.
// See hal/sim for a test simulator.
type Transport interface {
	// Init opens the underlying hardware resources.
	Init() error
	// Deinit releases hardware resources opened by Init.
	Deinit() error
	// CSNLow asserts the chip-select line (active low).
	CSNLow() error
	// CSNHigh deasserts the chip-select line.
	CSNHigh() error
	// Transfer performs a full-duplex SPI exchange in-place.
	// On return, buf contains the received bytes.
	Transfer(buf []byte) error
	// Delay blocks for at least ms milliseconds.
	Delay(ms uint32) error
	// RandomBytes fills buf with cryptographically random bytes.
	RandomBytes(buf []byte) error
}
