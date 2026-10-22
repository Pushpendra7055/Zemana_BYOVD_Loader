# 🔍 Zemana BYOVD Loader — Malware Analysis & YARA
### 🚨 Step-by-step investigation with embedded evidence screenshots

---

## 🚨 What if a Windows executable loads a vulnerable driver to target security software?

This repository documents a 64-bit Windows executable that identifies itself as a **BYOVD Loader (`zam64.sys`)**. The decompiled code shows it expects the driver beside the executable, attempts to set up the `ZemanaAM` driver service, opens the Zemana device interface, targets security-related processes and attempts credential-access actions.

> **Verdict: Malicious — high confidence.** The supplied console screenshot reports one security-process termination and three successful registry-hive save commands. The LSASS dump path is printed, but the dump has not been independently validated.

## 🧪 Investigation highlights

- **SHA-256:** `129f838cc7d6a60993aa1e622aa56b748fb511b9578d35c7da200e837c7cc291`
- **Format:** PE32+ / AMD64 console executable, 45,568 bytes
- **Driver expected beside sample:** `zam64.sys`
- **Service:** `ZemanaAM`
- **Device:** `\\.\ZemanaAntiMalware`
- **IOCTLs identified:** `0x80002010` and `0x80002048`
- **Credential-related actions:** SAM/SYSTEM/SECURITY hive saves and an LSASS MiniDump attempt

## 📸 Runtime evidence

![Console output from the supplied lab run](evidence/11-runtime-console-confirmation.png)

*The console reports driver/device initialization, trust registration, termination of `SecurityHealthService.exe`, three completed hive-save commands and the intended LSASS dump path. These are program messages; output files and host-side effects should be independently validated where available.*

## 🧭 Read the case study step by step

Open **[`blog/CASE-STUDY.md`](blog/CASE-STUDY.md)** for the full walkthrough, including the analysis screenshots (“snaps”) embedded beside each finding:

1. Identify the PE and record hashes.
2. Review strings and decompiled logic.
3. Trace construction of the sibling `zam64.sys` path.
4. Follow service creation and startup.
5. Inspect device access and IOCTL values.
6. Identify targeted security processes.
7. Compare the static analysis with runtime output.
8. Assess registry-hive saves and the LSASS dump attempt.
9. Review cleanup, public threat intelligence and remaining evidence gaps.
10. Run and validate the companion YARA rules.

## 📂 Repository contents

- [`blog/CASE-STUDY.md`](blog/CASE-STUDY.md) — step-by-step investigation with embedded screenshots.
- [`rules/zemana_byovd_loader.yar`](rules/zemana_byovd_loader.yar) — specific and broader hunting heuristics.
- [`indicators/IOCS.md`](indicators/IOCS.md) — metadata and observable indicators.
- [`evidence/`](evidence/) — 20 supplied DIE, PEStudio, IDA/decompiler, x64dbg, runtime and threat-intelligence screenshots.

## 🛡️ Run YARA

```bash
yara -r rules/zemana_byovd_loader.yar /path/to/authorized/sample-corpus/
```

The rules are heuristics and require validation against the original binary and a clean corpus. A match against the exact sample has **not** been independently verified because the original executable bytes were not available for YARA execution in the analysis workspace.

## 🧠 Key finding

> The loader expects `zam64.sys`; the supplied code does not establish who put it there.

Acquire the actual driver and correlate file-creation, parent-process, archive/installer and service telemetry to determine provenance. No specific threat actor, successful exfiltration or validated LSASS dump is established by the supplied artifacts.

## 📚 References

- [LOLDrivers — `zam64.sys`](https://www.loldrivers.io/drivers/e5f12b82-8d07-474e-9587-8c7b3714d60c/)
- [Malwarebytes — Exploit.CVE202131728](https://www.malwarebytes.com/blog/detections/exploit-cve202131728)
- [MITRE ATT&CK — LSASS Memory (T1003.001)](https://attack.mitre.org/techniques/T1003/001/)

---

**Disclaimer:** For defensive research and authorized incident response. Static analysis describes code capability; runtime claims are limited to the supplied screenshots. The original driver binary, raw endpoint telemetry and output dump files were not supplied.
