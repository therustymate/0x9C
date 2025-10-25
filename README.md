# 0x9C
PoC Ring3 RootKit | 0x9C - ERROR_SIGNAL_REFUSED

## Disclaimer

This document and all associated materials are provided strictly for **legitimate security research, education, and authorized antivirus detection capability testing purposes only.**
The techniques and concepts described herein involve advanced software security, malware analysis, and development methods, and **any unauthorized use, reproduction, distribution, or malicious deployment against systems without explicit permission is strictly prohibited.**

By accessing and utilizing this material, you acknowledge and agree to comply with all applicable laws and regulations,
and to obtain proper authorization before conducting any security testing or research activities.

The author and affiliated parties **expressly disclaim all legal liability and responsibility for any misuse, unauthorized actions, or damages arising from the use of this information.**

Furthermore, this research was conducted to study current antivirus detection limitations, develop evasion techniques for educational purposes, and enhance cybersecurity expertise.
The disclosure of this technology is purely for advancing the security industry and academic research.

Therefore, all risks, legal responsibilities, and consequences resulting from the use or misuse of this document rest solely with the user.
The author and related parties are fully indemnified from any direct or indirect damages.

By reading or using this document, you are deemed to have accepted all the above conditions.

## How does it work?
The user-mode rootkit is injected into the target process as a DLL. After injection it hooks `NtQuerySystemInformation`, examines `ImageName.Buffer` in the `PSYSTEM_PROCESS_INFORMATION` structure, and if it matches a process that should be hidden, it modifies `NextEntryOffset` to remove that process from the list and link directly to the next entry to prevent the process from being seen.