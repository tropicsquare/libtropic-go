# libtropic-go

Pure-Go host driver for the [TROPIC01](https://tropicsquare.com/tropic01) secure element.

This library implements the full TROPIC01 communication protocol (L1 SPI framing, L2 request/response, L3 Noise-encrypted session) with no CGo or external C dependencies. It is aligned with the reference [C library](https://github.com/tropicsquare/libtropic) and the [Rust crate](https://github.com/tropicsquare/libtropic-rs).

## Installation

```sh
go get libtropic-go
```

Requires Go 1.22 or later.

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "libtropic-go/tropic01"
    "libtropic-go/tropic01/keys"
    "libtropic-go/tropic01/hal/usbdongle"
)

func main() {
    // Open a USB devkit dongle.
    transport := usbdongle.New(usbdongle.Config{Port: "/dev/ttyACM0"})
    dev := tropic01.NewDevice(transport)
    if err := dev.Init(); err != nil {
        log.Fatal(err)
    }
    defer dev.Deinit()

    // Reboot the chip.
    if err := dev.Startup(tropic01.StartupReqReboot); err != nil {
        log.Fatal(err)
    }

    // Start an encrypted session using production keys (slot 0).
    if err := dev.SessionStart(keys.SH0PrivProd0[:], keys.SH0PubProd0[:], 0); err != nil {
        log.Fatal(err)
    }

    // Ping the chip.
    resp, err := dev.Ping([]byte("Hello TROPIC01!"))
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Ping response: %q\n", resp)

    // Clean up.
    dev.SessionAbort()
}
```

## Examples

The `cmd/tropic01-example-usb-devkit` binary demonstrates common TROPIC01 operations using a USB development kit dongle:

```sh
go build ./cmd/tropic01-example-usb-devkit
./tropic01-example-usb-devkit <command> [device_path]
```

| Command | Description |
|---------|-------------|
| `hello_world` | Reboot, start session, send ping, abort session |
| `identify_chip` | Read firmware versions, bank headers, and chip ID |
| `ecc_eddsa` | Generate Ed25519 key, sign messages, verify signatures |
| `full_chain_verification` | Read and export the certificate chain as DER files |

Default device path: `/dev/ttyACM0`

## API Overview

### Device Lifecycle (no session required)

`NewDevice`, `Init`, `Deinit`, `Startup`, `Sleep`

### Device Information (no session required)

`GetInfo`, `GetInfoChipID`, `GetInfoRiscvFWVer`, `GetInfoSpectFWVer`, `GetInfoFWBank`, `GetInfoCertStore`, `GetLogReq`

### Session Management

`SessionStart`, `SessionAbort`

### L3 Encrypted Commands (session required)

`Ping`, `RandomValueGet`, `ECCKeyGenerate`, `ECCKeyStore`, `ECCKeyRead`, `ECCKeyErase`, `ECDSASign`, `EdDSASign`, `PairingKeyWrite`, `PairingKeyRead`, `PairingKeyInvalidate`, `RMemDataWrite`, `RMemDataRead`, `RMemDataErase`, `RConfigWrite`, `RConfigRead`, `RConfigErase`, `IConfigWrite`, `IConfigRead`, `MCTRInit`, `MCTRUpdate`, `MCTRGet`, `MacAndDestroy`

See [LOWLEVEL.md](LOWLEVEL.md) for detailed API signatures, transport interface, constants, and protocol internals.

## Testing

```sh
go test ./...
```

Tests use the simulator transport (`tropic01/hal/sim`) and require no hardware.

## License

See [LICENSE](LICENSE) for details.
