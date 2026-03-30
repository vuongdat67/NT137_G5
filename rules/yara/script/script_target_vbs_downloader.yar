rule Script_Target_VBS_Downloader
{
    meta:
        description = "VBScript downloader behavior patterns"
        platform = "Cross"
        target = "Script"
        family = "Generic.VBS.Downloader"
        severity = "medium"
    strings:
        $v1 = "CreateObject(\"MSXML2.XMLHTTP\")" ascii nocase
        $v2 = "CreateObject(\"ADODB.Stream\")" ascii nocase
        $v3 = "WScript.Shell" ascii nocase
        $v4 = "SaveToFile" ascii nocase
        $v5 = "http://" ascii nocase
        $v6 = "https://" ascii nocase
    condition:
        (2 of ($v1,$v2,$v3,$v4) and 1 of ($v5,$v6))
}
