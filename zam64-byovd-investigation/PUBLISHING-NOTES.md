# Publishing notes

**Suggested GitHub repository name:** `zemana-zam64-byovd-analysis`

**Suggested repository description:** Static reverse-engineering case study of a Zemana `zam64.sys` BYOVD loader, with evidence screenshots, host-hunting notes, and YARA rules.

**Suggested topics:** `malware-analysis`, `reverse-engineering`, `yara`, `threat-hunting`, `windows-security`, `byovd`, `incident-response`

**Suggested social/README blurb:**

> A combined static and screenshot-supported runtime case study of a Windows x64 loader that expects a Zemana `zam64.sys` driver beside itself, invokes the driver through `\\.\ZemanaAntiMalware`, attempts to terminate security processes, and attempts SAM/SYSTEM/SECURITY hive saves plus an LSASS dump. Includes DIE/PEStudio/IDA/x64dbg and console evidence screenshots, plus two heuristic YARA rules. Runtime screenshot evidence reports one successful security-process termination and three successful hive saves; the LSASS dump file itself remains unverified. The driver's on-host provenance remains unresolved without host telemetry.

Before publishing, review the included screenshots for any environment-specific paths or identifiers you do not want public. The screenshots show a lab-style Windows path and transient PIDs; redact them if that information is sensitive in your organization. Do not publish real registry-hive exports or LSASS dumps.
