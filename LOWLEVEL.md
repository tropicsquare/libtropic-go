# Low-Level Reference

Detailed API signatures, transport interface, constants, and protocol internals for libtropic-go.

## Package Layout

```
libtropic-go/
  go.mod
  tropic01/                          # Core library (package tropic01)
    api.go                           # Public device API
    device.go                        # Device struct and Init/Deinit
    constants.go                     # Protocol constants
    transport.go                     # Transport interface
    errors.go                        # Error types
    l1.go, l2.go, l3.go             # Protocol layer implementations
    crypto.go, crc16.go             # Cryptographic and checksum helpers
    session.go, options.go          # Session state and config options
    keys/                            # Pre-shared pairing keys
    hal/
      linux/                         # Linux spidev + GPIO v2 transport
      sim/                           # Test simulator transport
      usbdongle/                     # USB development kit serial transport
    internal/
      asn1der/                       # Minimal ASN.1 DER parser
  cmd/
    tropic01-example-usb-devkit/     # Example CLI using a USB devkit dongle
```

## API Reference

### Device Lifecycle (no session required)

| Method | Description |
|--------|-------------|
| `NewDevice(t Transport, opts ...Option) *Device` | Create a new device handle |
| `Init() error` | Initialize the transport |
| `Deinit() error` | Release transport resources |
| `Startup(startupID byte) error` | Reboot the chip |
| `Sleep(sleepKind byte) error` | Enter sleep or deep-sleep mode |

### Device Information (no session required)

| Method | Description |
|--------|-------------|
| `GetInfo(objectID, blockIndex byte) ([]byte, error)` | Raw L2 GET_INFO request |
| `GetInfoChipID() ([]byte, error)` | Read chip ID |
| `GetInfoRiscvFWVer() ([]byte, error)` | Read RISC-V firmware version |
| `GetInfoSpectFWVer() ([]byte, error)` | Read SPECT firmware version |
| `GetInfoFWBank(bankID byte) ([]byte, error)` | Read firmware bank header |
| `GetInfoCertStore() ([]byte, error)` | Read certificate store (multi-block) |
| `GetLogReq() ([]byte, error)` | Read device log |

### Session Management

| Method | Description |
|--------|-------------|
| `SessionStart(shPriv, shPub []byte, pkeyIndex byte) error` | Noise_KK1 handshake (reads chip cert internally) |
| `SessionAbort() error` | Abort the current session |

### L3 Encrypted Commands (session required)

| Method | Description |
|--------|-------------|
| `Ping(data []byte) ([]byte, error)` | Echo test |
| `PairingKeyWrite(slot byte, key []byte) error` | Write pairing public key (slot 0-3) |
| `PairingKeyRead(slot byte) ([]byte, error)` | Read pairing public key |
| `PairingKeyInvalidate(slot byte) error` | Invalidate pairing key |
| `RMemDataWrite(slot uint16, data []byte) error` | Write to R-Memory user partition |
| `RMemDataRead(slot uint16) ([]byte, error)` | Read from R-Memory user partition |
| `RMemDataErase(slot uint16) error` | Erase R-Memory user partition slot |
| `RConfigWrite(address uint16, value uint32) error` | Write R-Config register |
| `RConfigRead(address uint16) (uint32, error)` | Read R-Config register |
| `RConfigErase() error` | Erase R-Config area |
| `IConfigWrite(address uint16, bitIndex byte) error` | Write I-Config bit |
| `IConfigRead(address uint16) (uint32, error)` | Read I-Config register |
| `ECCKeyGenerate(slot byte, curve byte) error` | Generate ECC key pair |
| `ECCKeyStore(slot byte, curve byte, key []byte) error` | Store private ECC key |
| `ECCKeyRead(slot byte) ([]byte, error)` | Read public ECC key |
| `ECCKeyErase(slot byte) error` | Erase ECC key |
| `ECDSASign(slot byte, hash []byte) ([]byte, error)` | ECDSA signature (P-256) |
| `EdDSASign(slot byte, msg []byte) ([]byte, error)` | EdDSA signature (Ed25519) |
| `MCTRInit(slot byte, value uint32) error` | Initialize monotonic counter |
| `MCTRUpdate(slot byte) error` | Increment monotonic counter |
| `MCTRGet(slot byte) (uint32, error)` | Read monotonic counter |
| `MacAndDestroy(slot uint16, dataIn []byte) ([]byte, error)` | Compute MAC and destroy key |
| `RandomValueGet(n byte) ([]byte, error)` | Get random bytes from the chip |

## Transport Interface

The `Transport` interface abstracts the physical communication layer:

```go
type Transport interface {
    Init() error
    Deinit() error
    CSNLow() error
    CSNHigh() error
    Transfer(buf []byte) error
    Delay(ms uint32) error
    RandomBytes(buf []byte) error
}
```

Three implementations are provided:

| Package | Description |
|---------|-------------|
| `tropic01/hal/linux` | Linux spidev + GPIO v2 character-device UAPI. Directly controls SPI and chip-select via kernel ioctls. Linux only. |
| `tropic01/hal/sim` | Test simulator with queued-response and stateful modes. No hardware required. |
| `tropic01/hal/usbdongle` | USB development kit (CDC ACM serial). Hex-encodes SPI frames over a 115200-baud serial port. |

## Pre-Shared Keys

The `tropic01/keys` package provides well-known pairing keys:

| Variable | Description |
|----------|-------------|
| `SH0PrivEngSample` | Host private key for engineering sample chips |
| `SH0PubEngSample` | Host public key for engineering sample chips |
| `SH0PrivProd0` | Host private key for production chips |
| `SH0PubProd0` | Host public key for production chips |

## Constants

Commonly used constants exported from the `tropic01` package:

| Constant | Value | Description |
|----------|-------|-------------|
| `EccCurveP256` | `0x01` | NIST P-256 curve |
| `EccCurveEd25519` | `0x02` | Ed25519 curve |
| `ECCSlotMax` | `31` | Maximum ECC key slot index |
| `RMemDataSlotMax` | `511` | Maximum R-Memory data slot index |
| `PairingKeySlotMax` | `3` | Maximum pairing key slot index |
| `MacAndDestroySlotMax` | `127` | Maximum MAC-and-destroy slot index |
| `MCounterValueMax` | `0xFFFFFFFE` | Maximum monotonic counter value |
| `StartupReqReboot` | `0x01` | Normal reboot |
| `StartupReqMaintenanceReboot` | `0x03` | Maintenance/bootloader reboot |
| `SleepReqSleep` | `0x05` | Light sleep |
| `SleepReqDeepSleep` | `0x0a` | Deep sleep |
| `BankIDRiscvFw1` | `1` | RISC-V firmware bank 1 |
| `BankIDRiscvFw2` | `2` | RISC-V firmware bank 2 |
| `BankIDSpectFw1` | `17` | SPECT firmware bank 1 |
| `BankIDSpectFw2` | `18` | SPECT firmware bank 2 |

## Protocol Overview

The TROPIC01 protocol has three layers:

- **L1 (SPI)** -- Physical SPI transactions with chip-select control and status polling.
- **L2 (Framing)** -- Request/response framing with CRC-16 integrity checks. Handles GET_INFO, HANDSHAKE, SLEEP, STARTUP, and encrypted command wrapping.
- **L3 (Encryption)** -- AES-256-GCM encrypted commands over a Noise_KK1_25519_AESGCM_SHA256 session. All sensitive operations (key management, signing, memory access) go through L3.
