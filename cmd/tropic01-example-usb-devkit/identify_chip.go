package main

import (
	"encoding/hex"
	"fmt"

	tropic01 "libtropic-go/tropic01"
)

func runIdentifyChip(dev *tropic01.Device) error {
	fmt.Println("=== Identify Chip Example ===")

	// Reboot chip.
	fmt.Println("Rebooting chip...")
	if err := dev.Startup(tropic01.StartupReqReboot); err != nil {
		return fmt.Errorf("startup: %w", err)
	}

	// Read RISC-V FW version.
	riscvVer, err := dev.GetInfoRiscvFWVer()
	if err != nil {
		return fmt.Errorf("get RISC-V FW version: %w", err)
	}
	fmt.Printf("RISC-V FW version: %s\n", hex.EncodeToString(riscvVer))

	// Read SPECT FW version.
	spectVer, err := dev.GetInfoSpectFWVer()
	if err != nil {
		return fmt.Errorf("get SPECT FW version: %w", err)
	}
	fmt.Printf("SPECT FW version:  %s\n", hex.EncodeToString(spectVer))

	// Maintenance reboot to read bootloader version.
	fmt.Println("Maintenance reboot...")
	if err := dev.Startup(tropic01.StartupReqMaintenanceReboot); err != nil {
		return fmt.Errorf("maintenance reboot: %w", err)
	}

	// Read bootloader (RISC-V FW version in maintenance mode).
	blVer, err := dev.GetInfoRiscvFWVer()
	if err != nil {
		return fmt.Errorf("get bootloader version: %w", err)
	}
	fmt.Printf("Bootloader version: %s\n", hex.EncodeToString(blVer))

	// Read all 4 firmware bank headers.
	bankNames := []string{"RISC-V FW1", "RISC-V FW2", "SPECT FW1", "SPECT FW2"}
	bankIDs := []byte{tropic01.BankIDRiscvFw1, tropic01.BankIDRiscvFw2, tropic01.BankIDSpectFw1, tropic01.BankIDSpectFw2}
	for i, bankID := range bankIDs {
		header, err := dev.GetInfoFWBank(bankID)
		if err != nil {
			fmt.Printf("FW bank %s: error: %v\n", bankNames[i], err)
			continue
		}
		fmt.Printf("FW bank %s: %s\n", bankNames[i], hex.EncodeToString(header))
	}

	// Read chip ID.
	chipID, err := dev.GetInfoChipID()
	if err != nil {
		return fmt.Errorf("get chip ID: %w", err)
	}
	fmt.Printf("Chip ID: %s\n", hex.EncodeToString(chipID))

	fmt.Println("Done!")
	return nil
}
