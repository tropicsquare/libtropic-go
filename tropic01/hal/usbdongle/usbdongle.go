// Package usbdongle provides a TROPIC01 Transport implementation for USB
// development kits that expose a serial (CDC ACM) interface.
//
// The protocol is text-based: hex-encoded SPI frames are exchanged over
// a serial port at 115200 baud, 8N1. This mirrors the Rust
// tropic01-example-usb-devkit crate's usb_dongle module.
package usbdongle

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.bug.st/serial"
)

// Config holds configuration for the USB dongle transport.
type Config struct {
	// Port is the serial port path, e.g. "/dev/ttyACM0".
	Port string
}

// Transport implements the tropic01.Transport interface over a USB serial dongle.
type Transport struct {
	cfg  Config
	port serial.Port
	rd   *bufio.Reader
}

// New creates a new USB dongle transport. Call Init before use.
func New(cfg Config) *Transport {
	return &Transport{cfg: cfg}
}

// Init opens the serial port at 115200 baud, 8N1.
func (t *Transport) Init() error {
	mode := &serial.Mode{
		BaudRate: 115200,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}
	port, err := serial.Open(t.cfg.Port, mode)
	if err != nil {
		return fmt.Errorf("usbdongle: open %s: %w", t.cfg.Port, err)
	}
	if err := port.SetReadTimeout(5 * time.Second); err != nil {
		port.Close()
		return fmt.Errorf("usbdongle: set timeout: %w", err)
	}
	t.port = port
	t.rd = bufio.NewReader(port)
	return nil
}

// Deinit closes the serial port.
func (t *Transport) Deinit() error {
	if t.port != nil {
		err := t.port.Close()
		t.port = nil
		t.rd = nil
		return err
	}
	return nil
}

// CSNLow is a no-op for the USB dongle.
// The dongle firmware automatically asserts CS when it receives a hex exchange
// command, so no explicit CS assert is needed.
func (t *Transport) CSNLow() error {
	return nil
}

// CSNHigh deasserts chip-select by sending "CS=0\n" to the dongle.
// This tells the dongle firmware to release the CS line after a transfer.
func (t *Transport) CSNHigh() error {
	return t.sendExpectOK("CS=0\n")
}

// Transfer performs a full-duplex SPI exchange via the dongle.
// The TX bytes are hex-encoded, sent as "<HEX>x\n", and the hex response
// is decoded back into buf.
func (t *Transport) Transfer(buf []byte) error {
	if t.port == nil {
		return errors.New("usbdongle: port not open")
	}
	// Send hex-encoded data followed by "x\n" (exchange command).
	hexStr := strings.ToUpper(hex.EncodeToString(buf)) + "x\n"
	if _, err := t.port.Write([]byte(hexStr)); err != nil {
		return fmt.Errorf("usbdongle: write: %w", err)
	}

	// Small delay for the dongle to process.
	time.Sleep(10 * time.Millisecond)

	// Read response line.
	line, err := t.rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("usbdongle: read response: %w", err)
	}
	line = strings.TrimSpace(line)

	// Decode hex response into buf.
	decoded, err := hex.DecodeString(line)
	if err != nil {
		return fmt.Errorf("usbdongle: decode response %q: %w", line, err)
	}
	copy(buf, decoded)
	return nil
}

// Delay blocks for at least ms milliseconds.
func (t *Transport) Delay(ms uint32) error {
	time.Sleep(time.Duration(ms) * time.Millisecond)
	return nil
}

// RandomBytes fills buf with cryptographically random bytes.
func (t *Transport) RandomBytes(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}

// sendExpectOK sends a command and expects "OK\r\n" in response.
func (t *Transport) sendExpectOK(cmd string) error {
	if t.port == nil {
		return errors.New("usbdongle: port not open")
	}
	if _, err := t.port.Write([]byte(cmd)); err != nil {
		return fmt.Errorf("usbdongle: write %q: %w", cmd, err)
	}
	time.Sleep(10 * time.Millisecond)
	line, err := t.rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("usbdongle: read response for %q: %w", cmd, err)
	}
	line = strings.TrimSpace(line)
	if line != "OK" {
		return fmt.Errorf("usbdongle: expected OK, got %q", line)
	}
	return nil
}
