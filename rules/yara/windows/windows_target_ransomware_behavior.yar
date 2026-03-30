rule Windows_Target_Ransomware_Behavior
{
    meta:
        description = "Windows ransomware behavior markers (crypto + recovery tamper)"
        platform = "Windows"
        target = "PE"
        family = "Generic.Ransomware"
        severity = "high"
    strings:
        $c1 = "CryptEncrypt" ascii wide
        $c2 = "BCryptEncrypt" ascii wide
        $c3 = "AES" ascii wide
        $r1 = "vssadmin delete shadows" ascii wide nocase
        $r2 = "wmic shadowcopy delete" ascii wide nocase
        $n1 = "Your files have been encrypted" ascii wide nocase
        $n2 = ".locked" ascii wide
    condition:
        (1 of ($c*) and 1 of ($r*)) or (1 of ($c*) and 1 of ($n*))
}
