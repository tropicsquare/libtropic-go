package main

import (
	"fmt"

	tropic01 "libtropic-go/tropic01"
	"libtropic-go/tropic01/keys"
)

func runHelloWorld(dev *tropic01.Device) error {
	fmt.Println("=== Hello World Example ===")

	// Reboot chip.
	fmt.Println("Rebooting chip...")
	if err := dev.Startup(tropic01.StartupReqReboot); err != nil {
		return fmt.Errorf("startup: %w", err)
	}

	// Start secure session with production keys (slot 0).
	fmt.Println("Starting secure session...")
	if err := dev.SessionStart(keys.SH0PrivProd0[:], keys.SH0PubProd0[:], 0); err != nil {
		return fmt.Errorf("session start: %w", err)
	}

	// Send ping.
	msg := []byte("This is Hello World message from TROPIC01!!")
	fmt.Printf("Sending ping: %q\n", msg)
	resp, err := dev.Ping(msg)
	if err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	fmt.Printf("Received:     %q\n", resp)

	// Abort session.
	fmt.Println("Aborting session...")
	if err := dev.SessionAbort(); err != nil {
		return fmt.Errorf("session abort: %w", err)
	}

	fmt.Println("Done!")
	return nil
}
