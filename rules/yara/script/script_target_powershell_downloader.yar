rule Script_Target_PowerShell_Downloader
{
    meta:
        description = "PowerShell downloader / stager indicators"
        platform = "Cross"
        target = "Script"
        family = "Generic.Downloader"
        severity = "high"
    strings:
        $s1 = "powershell" ascii nocase
        $s2 = "-ExecutionPolicy Bypass" ascii nocase
        $s3 = "IEX(" ascii nocase
        $s4 = "DownloadString(" ascii nocase
        $s5 = "FromBase64String(" ascii nocase
        $s6 = "Invoke-WebRequest" ascii nocase
    condition:
        $s1 and 2 of ($s2,$s3,$s4,$s5,$s6)
}
