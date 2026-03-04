//go:build linux

// Package linux provides a TROPIC01 Transport implementation for Linux using
// spidev and the GPIO v2 character-device UAPI.
//
// It satisfies the libtropic.Transport interface structurally (duck-typing)
// without importing the parent module, avoiding circular dependencies.
//
// Usage:
//
//	cfg := linux.SPIConfig{
//	    SPIDevice: "/dev/spidev0.0",
//	    GPIOChip:  "/dev/gpiochip0",
//	    CSPin:     8,
//	    SpeedHz:   1_000_000,
//	}
//	t := linux.NewSPITransport(cfg)
//	if err := t.Init(); err != nil { ... }
//	defer t.Deinit()
package linux

import (
	"crypto/rand"
	"errors"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Linux kernel struct mirrors (no cgo)
//
// All sizes verified against kernel headers:
//   gpiochip_info              68 B
//   gpio_v2_line_attribute     16 B
//   gpio_v2_line_config_attribute 24 B
//   gpio_v2_line_config       272 B
//   gpio_v2_line_request      592 B
//   gpio_v2_line_values        16 B
//   spi_ioc_transfer           32 B
// ---------------------------------------------------------------------------

const (
	gpioMaxNameSize   = 32
	gpioV2LinesMax    = 64
	gpioV2NumAttrsMax = 10

	// GPIO v2 line flags (linux/gpio.h: enum gpio_v2_line_flag).
	// GPIO_V2_LINE_FLAG_OUTPUT = _BITULL(3) = 1 << 3 = 8.
	gpioV2LineFlagOutput = uint64(1 << 3)

	// GPIO v2 line attribute IDs (linux/gpio.h).
	// GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES = 2.
	gpioV2LineAttrIDOutputValues = uint32(2)

	// ioctl numbers (computed from kernel macros, see linux/gpio.h).
	// GPIO_GET_CHIPINFO_IOCTL  = _IOR(0xB4, 0x01, struct gpiochip_info[68])
	ioctlGPIOGetChipInfo = uintptr(0x8044b401)
	// GPIO_V2_GET_LINE_IOCTL  = _IOWR(0xB4, 0x07, struct gpio_v2_line_request[592])
	ioctlGPIOV2GetLine = uintptr(0xc250b407)
	// GPIO_V2_LINE_SET_VALUES_IOCTL = _IOWR(0xB4, 0x0F, struct gpio_v2_line_values[16])
	ioctlGPIOV2LineSetValues = uintptr(0xc010b40f)

	// SPI ioctl numbers (linux/spi/spidev.h, magic = 'k' = 0x6b).
	// SPI_IOC_MESSAGE(1) = _IOW('k', 0, n*sizeof(spi_ioc_transfer))
	//   struct spi_ioc_transfer is 32 bytes, so _IOW('k', 0, 32) = 0x40206b00.
	ioctlSPIMessage1 = uintptr(0x40206b00)
	// SPI_IOC_WR_MAX_SPEED_HZ = _IOW('k', 4, u32) = 0x40046b04
	ioctlSPIWrMaxSpeedHz = uintptr(0x40046b04)
	// SPI_IOC_WR_MODE32 = _IOW('k', 5, u32) = 0x40046b05
	ioctlSPIWrMode32 = uintptr(0x40046b05)
	// SPI_IOC_RD_MODE32 = _IOR('k', 5, u32) = 0x80046b05
	ioctlSPIRdMode32 = uintptr(0x80046b05)

	// SPI_MODE_0 = 0
	spiMode0 = uint32(0)

	defaultSpeedHz = uint32(1_000_000)
)

// gpiochipInfo mirrors struct gpiochip_info (linux/gpio.h).
// Size: name[32] + label[32] + lines(4) = 68 B.
type gpiochipInfo struct {
	Name  [gpioMaxNameSize]byte
	Label [gpioMaxNameSize]byte
	Lines uint32
}

// gpioV2LineAttribute mirrors struct gpio_v2_line_attribute (linux/gpio.h).
// Size: id(4) + padding(4) + union(8) = 16 B.
type gpioV2LineAttribute struct {
	ID      uint32
	Padding uint32
	Values  uint64 // union — use for GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES
}

// gpioV2LineConfigAttribute mirrors struct gpio_v2_line_config_attribute (linux/gpio.h).
// Size: attr(16) + mask(8) = 24 B.
type gpioV2LineConfigAttribute struct {
	Attr gpioV2LineAttribute
	Mask uint64
}

// gpioV2LineConfig mirrors struct gpio_v2_line_config (linux/gpio.h).
// Size: flags(8) + num_attrs(4) + padding[5](20) + attrs[10](240) = 272 B.
type gpioV2LineConfig struct {
	Flags    uint64
	NumAttrs uint32
	Padding  [5]uint32
	Attrs    [gpioV2NumAttrsMax]gpioV2LineConfigAttribute
}

// gpioV2LineRequest mirrors struct gpio_v2_line_request (linux/gpio.h).
// Size: offsets[64](256) + consumer[32](32) + config(272) + num_lines(4) +
//
//	event_buffer_size(4) + padding[5](20) + fd(4) = 592 B.
type gpioV2LineRequest struct {
	Offsets         [gpioV2LinesMax]uint32
	Consumer        [gpioMaxNameSize]byte
	Config          gpioV2LineConfig
	NumLines        uint32
	EventBufferSize uint32
	Padding         [5]uint32
	FD              int32
}

// gpioV2LineValues mirrors struct gpio_v2_line_values (linux/gpio.h).
// Size: bits(8) + mask(8) = 16 B.
type gpioV2LineValues struct {
	Bits uint64
	Mask uint64
}

// spiIOCTransfer mirrors struct spi_ioc_transfer (linux/spi/spidev.h).
// Size: tx_buf(8)+rx_buf(8)+len(4)+speed_hz(4)+delay_usecs(2)+
//
//	bits_per_word(1)+cs_change(1)+tx_nbits(1)+rx_nbits(1)+
//	word_delay_usecs(1)+pad(1) = 32 B.
type spiIOCTransfer struct {
	TxBuf          uint64
	RxBuf          uint64
	Len            uint32
	SpeedHz        uint32
	DelayUsecs     uint16
	BitsPerWord    uint8
	CSChange       uint8
	TxNbits        uint8
	RxNbits        uint8
	WordDelayUsecs uint8
	Pad            uint8
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// SPIConfig holds configuration for the Linux SPI transport.
type SPIConfig struct {
	// SPIDevice is the spidev path, e.g. "/dev/spidev0.0".
	SPIDevice string
	// GPIOChip is the GPIO character device path, e.g. "/dev/gpiochip0".
	GPIOChip string
	// CSPin is the GPIO line number to use for chip-select.
	CSPin uint32
	// SpeedHz is the SPI clock frequency in Hz. Defaults to 1_000_000 if zero.
	SpeedHz uint32
}

// SPITransport implements the libtropic.Transport interface using Linux kernel
// interfaces:
//   - /dev/spidevN.M  via SPI_IOC_MESSAGE ioctl
//   - /dev/gpiochipN  via GPIO character-device v2 UAPI
//
// Call Init before any other method, and Deinit when finished.
type SPITransport struct {
	cfg    SPIConfig
	spiFD  int // file descriptor for the SPI device
	gpioFD int // file descriptor for the GPIO chip
	csFD   int // file descriptor for the GPIO line request (CS pin)
}

// NewSPITransport creates a new Linux SPI transport. Call Init before use.
func NewSPITransport(cfg SPIConfig) *SPITransport {
	if cfg.SpeedHz == 0 {
		cfg.SpeedHz = defaultSpeedHz
	}
	return &SPITransport{
		cfg:    cfg,
		spiFD:  -1,
		gpioFD: -1,
		csFD:   -1,
	}
}

// Init opens the SPI device and claims the chip-select GPIO line.
// It configures SPI MODE 0 and sets the maximum speed.
// The CS line is initialised HIGH (de-asserted).
func (t *SPITransport) Init() error {
	// --- Open SPI device ---
	spiFD, err := syscall.Open(t.cfg.SPIDevice, syscall.O_RDWR, 0)
	if err != nil {
		return &initError{"open SPI device", t.cfg.SPIDevice, err}
	}
	t.spiFD = spiFD

	// Set SPI MODE 0.
	mode := spiMode0
	if err := ioctlPtr(t.spiFD, ioctlSPIWrMode32, unsafe.Pointer(&mode)); err != nil {
		t.closeAll()
		return &initError{"SPI_IOC_WR_MODE32", t.cfg.SPIDevice, err}
	}

	// Read back and verify the mode was accepted.
	var readMode uint32
	if err := ioctlPtr(t.spiFD, ioctlSPIRdMode32, unsafe.Pointer(&readMode)); err != nil {
		t.closeAll()
		return &initError{"SPI_IOC_RD_MODE32", t.cfg.SPIDevice, err}
	}
	if readMode != spiMode0 {
		t.closeAll()
		return errors.New("linux spi: device does not support SPI MODE 0")
	}

	// Set maximum speed.
	speed := t.cfg.SpeedHz
	if err := ioctlPtr(t.spiFD, ioctlSPIWrMaxSpeedHz, unsafe.Pointer(&speed)); err != nil {
		t.closeAll()
		return &initError{"SPI_IOC_WR_MAX_SPEED_HZ", t.cfg.SPIDevice, err}
	}

	// --- Open GPIO chip ---
	gpioFD, err := syscall.Open(t.cfg.GPIOChip, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.closeAll()
		return &initError{"open GPIO chip", t.cfg.GPIOChip, err}
	}
	t.gpioFD = gpioFD

	// Verify the chip is accessible via GPIO_GET_CHIPINFO_IOCTL.
	var chipInfo gpiochipInfo
	if err := ioctlPtr(t.gpioFD, ioctlGPIOGetChipInfo, unsafe.Pointer(&chipInfo)); err != nil {
		t.closeAll()
		return &initError{"GPIO_GET_CHIPINFO_IOCTL", t.cfg.GPIOChip, err}
	}

	// --- Request CS GPIO line as output, initially HIGH (de-asserted) ---
	var req gpioV2LineRequest
	req.Offsets[0] = t.cfg.CSPin
	req.NumLines = 1
	req.Config.Flags = gpioV2LineFlagOutput
	req.Config.NumAttrs = 1
	req.Config.Attrs[0].Attr.ID = gpioV2LineAttrIDOutputValues
	req.Config.Attrs[0].Attr.Values = 1 // initial value HIGH
	req.Config.Attrs[0].Mask = 1

	if err := ioctlPtr(t.gpioFD, ioctlGPIOV2GetLine, unsafe.Pointer(&req)); err != nil {
		t.closeAll()
		return &initError{"GPIO_V2_GET_LINE_IOCTL (CS)", t.cfg.GPIOChip, err}
	}
	t.csFD = int(req.FD)

	return nil
}

// Deinit releases all hardware resources opened by Init.
func (t *SPITransport) Deinit() error {
	t.closeAll()
	return nil
}

// CSNLow asserts the chip-select line (drives CS low, active).
func (t *SPITransport) CSNLow() error {
	v := gpioV2LineValues{
		Mask: 1,
		Bits: 0, // LOW — asserted
	}
	if err := ioctlPtr(t.csFD, ioctlGPIOV2LineSetValues, unsafe.Pointer(&v)); err != nil {
		return &ioctlError{"GPIO_V2_LINE_SET_VALUES_IOCTL (CSN low)", err}
	}
	return nil
}

// CSNHigh de-asserts the chip-select line (drives CS high, inactive).
func (t *SPITransport) CSNHigh() error {
	v := gpioV2LineValues{
		Mask: 1,
		Bits: 1, // HIGH — de-asserted
	}
	if err := ioctlPtr(t.csFD, ioctlGPIOV2LineSetValues, unsafe.Pointer(&v)); err != nil {
		return &ioctlError{"GPIO_V2_LINE_SET_VALUES_IOCTL (CSN high)", err}
	}
	return nil
}

// Transfer performs a full-duplex SPI exchange in-place using SPI_IOC_MESSAGE(1).
// On return, buf contains the bytes received from the device.
func (t *SPITransport) Transfer(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	ptr := uint64(uintptr(unsafe.Pointer(&buf[0])))
	xfer := spiIOCTransfer{
		TxBuf: ptr,
		RxBuf: ptr,
		Len:   uint32(len(buf)),
	}
	if err := ioctlPtr(t.spiFD, ioctlSPIMessage1, unsafe.Pointer(&xfer)); err != nil {
		return &ioctlError{"SPI_IOC_MESSAGE(1)", err}
	}
	return nil
}

// Delay blocks for at least ms milliseconds using nanosleep(2).
func (t *SPITransport) Delay(ms uint32) error {
	ts := syscall.NsecToTimespec(int64(ms) * 1_000_000)
	if err := syscall.Nanosleep(&ts, nil); err != nil {
		return err
	}
	return nil
}

// RandomBytes fills buf with cryptographically random bytes using crypto/rand.
func (t *SPITransport) RandomBytes(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ioctlPtr wraps syscall.Syscall for ioctl calls that pass a pointer argument.
func ioctlPtr(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// closeAll closes any open file descriptors, resetting them to -1.
func (t *SPITransport) closeAll() {
	if t.csFD >= 0 {
		syscall.Close(t.csFD)
		t.csFD = -1
	}
	if t.gpioFD >= 0 {
		syscall.Close(t.gpioFD)
		t.gpioFD = -1
	}
	if t.spiFD >= 0 {
		syscall.Close(t.spiFD)
		t.spiFD = -1
	}
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

type initError struct {
	op   string
	path string
	err  error
}

func (e *initError) Error() string {
	return "linux spi init: " + e.op + " " + e.path + ": " + e.err.Error()
}

func (e *initError) Unwrap() error { return e.err }

type ioctlError struct {
	op  string
	err error
}

func (e *ioctlError) Error() string {
	return "linux spi: " + e.op + ": " + e.err.Error()
}

func (e *ioctlError) Unwrap() error { return e.err }
