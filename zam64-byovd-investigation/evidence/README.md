# 📸 Evidence screenshots (“snaps”)

All 20 supplied screenshots are embedded in [`../blog/CASE-STUDY.md`](../blog/CASE-STUDY.md) near the step they support. They are illustrative evidence, not substitutes for raw endpoint telemetry.

| Snap | File | What it illustrates |
|---:|---|---|
| 1 | `01-detect-it-easy.png` | PE64 / AMD64 / console identification |
| 2 | `02-pestudio-metadata.png` | Hashes and PE metadata |
| 3 | `03-ida-driver-path-check.png` | Driver path construction and file-existence check |
| 4 | `12-x64dbg-driver-path.png` | Sibling driver path in debugger |
| 5 | `18-x64dbg-driver-path-check.png` | Driver path and file-attribute check |
| 6 | `04-ida-driver-service-management.png` | Service and driver-start logic |
| 7 | `13-x64dbg-service-setup-1.png` | Service setup in debugger |
| 8 | `14-x64dbg-createservice-call.png` | `CreateServiceA` callsite |
| 9 | `15-x64dbg-service-branch.png` | Service branch |
| 10 | `16-x64dbg-service-lookup-error.png` | Service lookup error in this run |
| 11 | `17-x64dbg-service-control-flow.png` | Service control flow |
| 12 | `19-x64dbg-service-create-branch.png` | Service creation branch |
| 13 | `20-x64dbg-device-and-ioctl.png` | Device open and `DeviceIoControl` |
| 14 | `05-ida-ioctl-and-credential-actions.png` | IOCTL and later actions in decompiled code |
| 15 | `07-ida-process-enumeration.png` | Process enumeration and name matching |
| 16 | `08-ida-process-termination-ioctl.png` | Termination helper and target PID |
| 17 | `11-runtime-console-confirmation.png` | Program output from runtime screenshot |
| 18 | `06-ida-lsass-and-argument-execution.png` | Registry-save and LSASS dump command construction |
| 19 | `09-public-threat-intelligence.png` | Screenshot of public TI research |
| 20 | `10-execution-flow-reference.png` | Summary of code-derived execution flow |

Do not publish recovered registry hives or LSASS dump files. The console line naming `C:\Windows\Temp\d.dmp` does not prove the dump exists or is valid.
