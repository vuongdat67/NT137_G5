rule Windows_Family_DarkSideRAT
{
    meta:
        description = "DarkSideRAT family marker"
        platform = "Windows"
        target = "PE"
        family = "DarkSideRAT"
        severity = "high"
    strings:
        $f1 = "DarkSideRAT" ascii wide nocase
        $f2 = "darksiderat" ascii wide nocase
        $ps1 = "powershell -ExecutionPolicy Bypass" ascii wide nocase
        $api1 = "WriteProcessMemory" ascii wide
        $api2 = "CreateRemoteThread" ascii wide
        $api3 = "NtCreateThreadEx" ascii wide
    condition:
        (1 of ($f*) and (1 of ($api*))) or (2 of ($api*) and $ps1)
}
