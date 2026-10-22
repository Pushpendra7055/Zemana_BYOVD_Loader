# Publishing notes

**Suggested GitHub repository name:** `zemana-byovd-loader-analysis`

**Suggested GitHub description:** Step-by-step reverse-engineering case study of a Zemana `zam64.sys` BYOVD loader, with selected IDA/x64dbg evidence, IOCs, and YARA heuristics.

**Suggested topics:** `malware-analysis`, `reverse-engineering`, `yara`, `threat-hunting`, `windows-security`, `byovd`, `incident-response`

The entire case study is the root `README.md`; there is no separate blog folder. Ten screenshots are embedded inline to show distinct checkpoints, including the process-enumeration loop, x64dbg process-termination control flow, the repeated “keep Defender dead” path, registry/LSASS command construction, and the console output.

Before making the repository public, review screenshots for host identifiers, usernames, internal paths, or other information you do not want to publish. The runtime screenshot's sample-directory path has been anonymized. Do not publish the original suspicious binary, a vulnerable driver unless you have a clear legal/operational reason, recovered registry hives, or LSASS dumps.

The YARA rules are unvalidated against the original executable bytes and should be presented as community hunting heuristics until tested against the original sample and a clean corpus. The LSASS dump attempt, exfiltration, and driver provenance remain unverified from the supplied artifacts.
