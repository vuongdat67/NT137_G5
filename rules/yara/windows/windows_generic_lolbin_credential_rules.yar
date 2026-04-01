rule Windows_Lolbin_Download_Execution_Generic
{
    meta:
        description = "Generic LOLBIN download/execute chain indicators"
        severity = "medium"
    strings:
        $l1 = "powershell -enc" nocase ascii wide
        $l2 = "bitsadmin /transfer" nocase ascii wide
        $l3 = "certutil -urlcache -split -f" nocase ascii wide
        $l4 = "regsvr32 /s /n /u /i:" nocase ascii wide
        $l5 = "mshta http" nocase ascii wide
        $l6 = "rundll32" nocase ascii wide
        $l7 = "wmic process call create" nocase ascii wide
    condition:
        2 of ($l*)
}

rule Windows_Credential_Theft_Artifacts_Generic
{
    meta:
        description = "Generic credential theft artifacts for local static scans"
        severity = "high"
    strings:
        $c1 = "sekurlsa::logonpasswords" nocase ascii wide
        $c2 = "mimikatz" nocase ascii wide
        $c3 = "lsass.exe" nocase ascii wide
        $c4 = "CryptUnprotectData" ascii wide
        $c5 = "CredEnumerateW" ascii wide
        $c6 = "sam\\" nocase ascii wide
    condition:
        2 of ($c*)
}
