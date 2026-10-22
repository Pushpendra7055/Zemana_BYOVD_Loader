# 📸 Selected investigation evidence

The report uses ten screenshots chosen for different investigative purposes. The x64dbg captures show disassembly, referenced strings, calls, and control-flow branches; they are **not, by themselves, proof that every shown instruction executed during the captured run**. The console image is application-generated output and should be corroborated with endpoint telemetry where possible.

| File | Purpose |
|---|---|
| `01-detect-it-easy.png` | PE format and architecture. |
| `02-pestudio-metadata.png` | Sample metadata and hashes. |
| `03-ida-driver-path-check.png` | Construction and validation of the sibling `zam64.sys` path. |
| `04-ida-driver-service-management.png` | `ZemanaAM` service lookup, creation, and start logic. |
| `05-ida-process-enumeration-loop.png` | `CreateToolhelp32Snapshot`, `Process32FirstW`, and `Process32NextW` logic used to enumerate processes and match a target name. |
| `06-x64dbg-device-control-target-list.png` | x64dbg view of device control, trust registration, security-process target names, and repeated helper calls. |
| `07-x64dbg-process-termination-branch.png` | x64dbg view of the `DeviceIoControl` result branch and success/failure messages for a process-termination request. |
| `08-x64dbg-keep-defender-loop.png` | x64dbg view of the “Keeping Defender dead for 30 seconds” path and recurring helper-call sequence. |
| `09-x64dbg-registry-and-lsass-commands.png` | Registry-hive save commands and LSASS dump command strings referenced in the main routine. |
| `10-runtime-console-confirmation.png` | Program-reported lab-run output; the sample-directory path has been anonymized. |

These screenshots illustrate the code and reported behavior. They do not replace the original executable, driver binary, debugger trace/log, Windows event logs, or file-system evidence. Do not publish recovered hives or LSASS dumps.
