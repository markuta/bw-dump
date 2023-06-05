package main

import (
	"os"
	"strconv"

	"github.com/0xrawsec/golang-win32/win32"
)

// TODO: add to to options
func writeMemoryRegions(pid int, baseAddress win32.ULONGLONG, mem []byte) error {
	memBaseAddrStr := strconv.FormatUint(uint64(baseAddress), 16) // use hex address
	outFileName := "dump-pid-" + strconv.Itoa(pid) + "-0x" + memBaseAddrStr + ".hex"

	f, err := os.Create(outFileName)
	if err != nil {
		return err
	}

	f.Write(mem)

	return nil

}
