# go-libtropic Design Document

**Date:** 2026-03-02
**Status:** Approved
**Reference:** [libtropic C library](../libtropic/) — the authoritative protocol spec and C implementation

---

## Overview

`go-libtropic` is a pure-Go port of [libtropic](https://github.com/tropicsquare/libtropic), the host-side
driver for the TROPIC01 secure element chip. It targets Go 1.26+ and relies exclusively on the Go standard
library. The library is designed to work on both Linux hosts (using the `spidev` kernel interface) and
baremetal Go runtimes such as [Tamago](https://github.com/usbarmory/tamago).

---

## Module

```
module go-libtropic

go 1.26
```

No external dependencies. All cryptographic primitives come from the Go standard library.

---

## Architecture: Transport Interface

The C library's HAL (hardware abstraction layer) — a set of platform-specific function implementations —
maps in Go to a single `Transport` interface. Any platform (Linux, Tamago, mock) provides a concrete type
that satisfies this interface.

```go
// Transport is the hardware abstraction layer for TROPIC01 communication.
// Implementations must be safe to call sequentially; concurrent access is
// the caller's responsibility.
type Transport interface {
    Init() error
    Deinit() error
    CSNLow() error
    CSNHigh() error
    // Transfer performs a full-duplex SPI exchange in-place.
    // On return, buf contains the received bytes.
    Transfer(buf []byte) error
    Delay(ms uint32) error
    RandomBytes(buf []byte) error
}
```

---

## Package Structure

```
go-libtropic/
├── go.mod
├── doc.go              // package-level godoc pointing to official docs
├── transport.go        // Transport interface
├── device.go           // Device struct, NewDevice, Init, Deinit
├── options.go          // functional options (WithLogger, WithTimeout)
├── errors.go           // Error type (iota enum, mirrors C lt_ret_t numbering)
├── constants.go        // protocol constants (frame sizes, offsets, timeouts)
├── l1.go               // Layer 1: SPI read/write, chip-status polling (unexported)
├── l2.go               // Layer 2: framing, CRC16, chunked send/receive (unexported)
├── l3.go               // Layer 3: AES-GCM encrypt/decrypt (unexported)
├── session.go          // secure session state + handshake logic (unexported)
├── crypto.go           // stdlib crypto wrappers: X25519, AES-GCM, HKDF, HMAC-SHA256
├── crc16.go            // CRC16/CCITT (CRC-16-IBM) implementation
├── api.go              // public Device methods (one per C lt_* function)
├── hal/
│   ├── linux/
│   │   └── spi.go      // Linux: spidev ioctl + GPIO v2 UAPI for CS pin
│   └── sim/
│       └── sim.go      // Simulator: queued-response mode + stateful chip mode
├── internal/
│   └── asn1der/
│       └── asn1der.go  // minimal ASN.1 DER subset for cert store parsing
└── *_test.go           // table-driven tests co-located with their packages
```

---

## Core Types

### Device

```go
type Device struct {
    t         Transport
    l2buf     [l1LenMax]byte  // shared L1/L2 frame buffer (mirrors lt_l2_state_t.buff)
    session   sessionState    // L3 AES-GCM keys, IVs, session status
    attrs     tr01Attrs       // FW-version-specific attributes (e.g. max R-mem slot size)
    logger    *slog.Logger
    timeoutMS uint32
}
```

`NewDevice(t Transport, opts ...Option) *Device` constructs a Device.
`device.Init()` initialises the transport and reads device attributes (mirrors `lt_init`).

### Errors

```go
type Error int

const (
    ErrFail          Error = 1
    ErrNoSession     Error = 2
    ErrParam         Error = 3
    ErrCrypto        Error = 4
    ErrAppFWTooNew   Error = 5
    // ... full list mirrors C lt_ret_t, preserving numeric values
)

func (e Error) Error() string  // returns human-readable description
```

### Options

```go
func WithLogger(l *slog.Logger) Option   // default: slog.Default()
func WithTimeout(ms uint32) Option       // default: LT_L1_TIMEOUT_MS_DEFAULT (70ms)
```

---

## Protocol Layers

### Layer 1 (`l1.go`)

Mirrors `lt_l1_read` / `lt_l1_write`:
- `l1Write(d *Device, length int) error` — assert CSN low, `Transfer`, deassert CSN high
- `l1Read(d *Device) error` — poll chip-status byte, retry up to 50 times with 25 ms delay,
  read STATUS+LEN, read remaining frame bytes

### Layer 2 (`l2.go`)

Mirrors `lt_l2_send` / `lt_l2_receive` / `lt_l2_send_encrypted_cmd` / `lt_l2_recv_encrypted_res`:
- CRC16 appended on send, verified on receive
- L3 payload chunked into ≤ 252-byte data fields
- Reassembled on receive (loop bounded to 42 iterations)

### Layer 3 (`l3.go`, `session.go`, `crypto.go`)

Mirrors `lt_out__*` / `lt_in__*` functions:
- AES-256-GCM with per-direction nonces (12-byte IV, incremented per message)
- Session handshake: X25519 ephemeral keygen → HKDF → derive encryption/decryption keys
- `sessionState.status` distinguishes ON / OFF (prevents L3 commands without a session)

---

## Cryptography

All primitives from Go stdlib:

| Primitive        | Go package                        |
|------------------|-----------------------------------|
| X25519           | `crypto/ecdh` (`ecdh.X25519()`)   |
| AES-256-GCM      | `crypto/aes` + `crypto/cipher`    |
| HMAC-SHA256      | `crypto/hmac` + `crypto/sha256`   |
| HKDF             | `crypto/hkdf` (Go 1.24+)          |
| CSPRNG           | `crypto/rand`                     |
| ASN.1 DER        | `encoding/asn1`                   |

No external crypto dependencies.

---

## HAL Implementations

### `hal/linux/spi.go`

Uses:
- `syscall.Open` + `SPI_IOC_MESSAGE` ioctl for SPI transfers (mode 0, configurable speed)
- Linux GPIO v2 UAPI (`GPIO_V2_GET_LINE_IOCTL`, `GPIO_V2_LINE_SET_VALUES_IOCTL`) for CS pin
- `syscall.Syscall(SYS_GETRANDOM, ...)` for entropy (mirrors `getrandom(2)`)
- `time.Sleep` for delays

Configuration passed via `LinuxSPIConfig` struct (SPI device path, GPIO chip path, CS pin number, SPI speed).

### `hal/sim/sim.go`

Implements `Transport`. Two modes:

**Queued mode** (`NewQueued() *Sim`):
- Pre-load raw frame bytes via `Sim.EnqueueResponse(data []byte)`
- Each `Transfer` call copies from the head of the queue into `buf`
- Advancing the queue happens on `CSNHigh()`
- Used in unit tests to verify protocol encoding without a real chip

**Stateful mode** (`NewStateful() *Sim`):
- Maintains in-memory chip state: ECC key slots (32 slots), R-mem slots, pairing keys, monotonic counters
- Parses incoming L2 frames, decodes L2 command IDs, generates correct L2 responses
- Supports all L2 and L3 commands the Go library exposes
- Does NOT implement the full TROPIC01 security model (e.g. no persistent I-config locking)

---

## Testing Strategy

- Table-driven tests for: CRC16, L2 frame check, L3 encrypt/decrypt round-trip, error string mapping
- API-level tests use `hal/sim` (both queued and stateful)
- No build tags; tests compile and run on any Go platform

---

## Logging

`Device` holds a `*slog.Logger`. All internal log calls use `d.logger.Debug(...)`. Users who want
no logging pass `slog.New(slog.NewTextHandler(io.Discard, nil))` via `WithLogger`.

---

## Non-goals

- Firmware update (`lt_mutable_fw_update`) — stubbed with `ErrNotImplemented` initially
- INT pin support — polling-only mode; INT pin variant can be added via an optional interface later
- Certificate chain verification — the library parses the cert store to extract STPUB (same as C); full
  chain verification is left to the caller using stdlib `crypto/x509`
