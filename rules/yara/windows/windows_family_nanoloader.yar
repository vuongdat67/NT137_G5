rule Windows_Family_NanoLoader
{
    meta:
        description = "NanoLoader-like downloader and process execution pattern"
        platform = "Windows"
        target = "PE"
        family = "NanoLoader"
        severity = "high"
    strings:
        $f1 = "NanoLoader" ascii wide nocase
        $cmd1 = "cmd /c" ascii wide nocase
        $ps1 = "powershell" ascii wide nocase
        $net1 = "WinHttpOpen" ascii wide
        $net2 = "URLDownloadToFile" ascii wide
        $proc1 = "CreateProcessW" ascii wide
    condition:
        ($f1 and (1 of ($net*) or $proc1)) or ($cmd1 and $ps1 and 1 of ($net*))
}
