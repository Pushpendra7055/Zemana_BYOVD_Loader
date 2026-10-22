# Indicators and Observable Artifacts

## Sample identifiers

| Type | Value | Source / caveat |
|---|---|---|
| File name | `47E9A22D7F29AFB76EB515574DE45BCC.fil` | PEstudio / metadata export |
| MD5 | `47e9a22d7f29afb76eb515574de45bcc` | PE metadata export |
| SHA-1 | `b858bebbe6e0059cb887dfc8f7b98cde60c2a8c3` | PE metadata export |
| SHA-256 | `129f838cc7d6a60993aa1e622aa56b748fb511b9578d35c7da200e837c7cc291` | PE metadata export; sample hash, not the decompiled listing hash |
| File size | 45,568 bytes | PE metadata export |
| Image type | PE32+ / AMD64 / console | DIE and PE metadata |
| Signature | Not signed, per metadata export | Does not alone prove maliciousness |
| Imphash | `d82a4e7b645e2bc2bb595a666e3a0188` | PEStudio screenshot; verify if recalculating against original PE |

## High-value strings

```text
BYOVD Loader (zam64.sys)
zam64.sys
ZemanaAM
\\.\ZemanaAntiMalware
MpDefenderCoreService.exe
MsMpEng.exe
reg save HKLM\SAM C:\Windows\Temp\s.dat /y
reg save HKLM\SYSTEM C:\Windows\Temp\sy.dat /y
reg save HKLM\SECURITY C:\Windows\Temp\se.dat /y
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump
```

## Behavior indicators

- Service name `ZemanaAM` created/started as a kernel-driver service.
- Device handle opened for `\\.\ZemanaAntiMalware`.
- `DeviceIoControl` call using IOCTL `0x80002010` with current PID to register the process as trusted.
- `DeviceIoControl` call using IOCTL `0x80002048` with a target PID to request process termination.
- Process-enumeration target names: `MsMpEng.exe`, `MpDefenderCoreService.exe`, `NisSrv.exe`, `SecurityHealthService.exe`, `MpCmdRun.exe`, `MsSense.exe`, `SenseIR.exe`.
- Intended output paths: `C:\Windows\Temp\s.dat`, `sy.dat`, `se.dat`, `d.dmp`.
- Optional command-line argument passed to `system()`.

## Provenance warning

These are indicators of this loader's code, not proof that every operation succeeded on a particular endpoint. The reviewed code expects `zam64.sys` in its own directory; it does not disclose the file's original delivery source.
