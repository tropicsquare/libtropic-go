// Command tropic01-example-usb-devkit demonstrates TROPIC01 operations via a
// USB development kit dongle.
//
// Usage:
//
//	tropic01-example-usb-devkit <command> [device_path]
//
// Commands: hello_world, identify_chip, ecc_eddsa, full_chain_verification
// Default device_path: /dev/ttyACM0
package main

import (
	"fmt"
	"os"

	tropic01 "libtropic-go/tropic01"
	"libtropic-go/tropic01/hal/usbdongle"
)

const defaultDevice = "/dev/ttyACM0"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [device_path]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Commands: hello_world, identify_chip, ecc_eddsa, full_chain_verification")
		os.Exit(1)
	}

	command := os.Args[1]
	devicePath := defaultDevice
	if len(os.Args) > 2 {
		devicePath = os.Args[2]
	}

	transport := usbdongle.New(usbdongle.Config{Port: devicePath})
	dev := tropic01.NewDevice(transport)

	if err := dev.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Init failed: %v\n", err)
		os.Exit(1)
	}
	defer dev.Deinit()

	var err error
	switch command {
	case "hello_world":
		err = runHelloWorld(dev)
	case "identify_chip":
		err = runIdentifyChip(dev)
	case "ecc_eddsa":
		err = runECCEdDSA(dev)
	case "full_chain_verification":
		err = runFullChainVerification(dev)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
