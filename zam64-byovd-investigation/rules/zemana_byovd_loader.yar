import "pe"

/*
  Detection: Zemana-driver BYOVD loader / security-process terminator
  Scope: Static PE files; string-based heuristics derived from one analyzed sample.
  Validate against your own clean corpus and tune before production deployment.
*/
rule WIN_Zemana_BYOVD_Loader_HighConfidence
{
    meta:
        description = "Detects a Windows PE matching the observed Zemana BYOVD loader and credential-dump behavior"
        author = "Defensive analysis - community rule"
        date = "2026-10-22"
        sample_sha256 = "129f838cc7d6a60993aa1e622aa56b748fb511b9578d35c7da200e837c7cc291"
        confidence = "High-specificity heuristic; not binary-validated against original PE bytes"
        reference = "https://www.loldrivers.io/drivers/e5f12b82-8d07-474e-9587-8c7b3714d60c/"

    strings:
        $banner       = "BYOVD Loader (zam64.sys)" ascii wide
        $driver       = "zam64.sys" ascii wide nocase
        $service      = "ZemanaAM" ascii wide
        $device       = "\\\\.\\ZemanaAntiMalware" ascii wide

        $reg_sam      = "reg save HKLM\\SAM C:\\Windows\\Temp\\s.dat /y" ascii wide
        $reg_system   = "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sy.dat /y" ascii wide
        $reg_security = "reg save HKLM\\SECURITY C:\\Windows\\Temp\\se.dat /y" ascii wide
        $lsass_dump   = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump" ascii wide
        $trusted      = "registered as trusted" ascii wide nocase
        $defender     = "MpDefenderCoreService.exe" ascii wide

    condition:
        pe.is_pe and
        2 of ($banner, $driver, $service, $device) and
        (
            2 of ($reg_*) or
            ($lsass_dump and ($trusted or $defender))
        )
}

rule WIN_Zemana_BYOVD_Behavior_Cluster_Hunt
{
    meta:
        description = "Hunt rule for related PE variants retaining Zemana driver artifacts and security-disabling or credential-dump strings"
        author = "Defensive analysis - community rule"
        date = "2026-10-22"
        confidence = "Medium; triage matches manually"
        note = "Designed to catch some variants even if the loader banner or zam64.sys filename changes"

    strings:
        $service      = "ZemanaAM" ascii wide
        $device       = "\\\\.\\ZemanaAntiMalware" ascii wide
        $driver64     = "zam64.sys" ascii wide nocase
        $driverguard  = "zamguard64.sys" ascii wide nocase

        $defender1    = "MsMpEng.exe" ascii wide
        $defender2    = "MpDefenderCoreService.exe" ascii wide
        $defender3    = "SenseIR.exe" ascii wide
        $reg_sam      = "reg save HKLM\\SAM" ascii wide
        $lsass_dump   = "comsvcs.dll, MiniDump" ascii wide
        $trusted      = "registered as trusted" ascii wide nocase

    condition:
        pe.is_pe and
        2 of ($service, $device, $driver*) and
        2 of ($defender*, $reg_sam, $lsass_dump, $trusted)
}
