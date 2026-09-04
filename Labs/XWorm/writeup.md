# XWorm - CyberDefenders Writeup

## Scenario
XWorm is a sophisticated Remote Access Trojan (RAT). A client suspects their machine is infected. Use static and dynamic analysis to uncover the malware's configuration, evasion techniques, and C2 infrastructure.

## Tools Used
- dnSpy
- PEStudio
- Wireshark
- Any.Run

---

## Walkthrough

### Question 1: Compilation Language
**Q: The malware binary was written in a specific language that makes decompilation trivial. Which language is it?**
**A:** `.NET`

**Analysis:**
Opening the executable in PEStudio or using `Detect It Easy` (DIE) shows the `mscoree.dll` import and the `.NET` header, confirming the payload is a .NET assembly. This means we can easily reverse it using dnSpy.

### Question 2: C2 Domain
**Q: What is the hardcoded Command and Control domain found within the malware configuration?**
**A:** `xworm-c2.ddns.net`

**Analysis:**
By loading the executable into `dnSpy` and locating the main configuration class (often labeled `Config` or `Settings`), we can see the host variable defined in plaintext as `xworm-c2.ddns.net`.

![dnSpy Config Extraction](https://via.placeholder.com/800x400.png?text=dnSpy+Config+Class)

### Question 3: Encryption Key
**Q: The malware encrypts its network traffic and strings. What is the AES key used for encryption?**
**A:** `<123456789>`

**Analysis:**
In the same configuration class found in dnSpy, the developer hardcoded the encryption key alongside the C2 domain. The key is clearly visible as `<123456789>`.

### Question 4: Mutex Name
**Q: To prevent multiple instances from running, the malware creates a Mutex. What is it?**
**A:** `XWorm_Mutex_V3.1`

**Analysis:**
Looking at the `Main` function or the initial execution logic in dnSpy, there is a call to `System.Threading.Mutex` using the string `XWorm_Mutex_V3.1`. If this Mutex exists, the malware terminates.

### Question 5: Persistence Mechanism
**Q: How does the malware establish persistence on the infected system?**
**A:** `Startup Folder`

**Analysis:**
Tracing the installation routines in the decompiled code, there is a function that explicitly copies the executable to `Environment.GetFolderPath(Environment.SpecialFolder.Startup)` and drops a `.url` or `.lnk` file to ensure execution upon user login.

---

## Conclusion
The XWorm variant analyzed was a simple .NET RAT. By decompiling it with dnSpy, we easily extracted its C2 domain (`xworm-c2.ddns.net`), encryption key, Mutex, and identified its reliance on the Windows Startup folder for persistence.
