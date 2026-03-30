rule Windows_Family_RustyStealer
{
    meta:
        description = "RustyStealer style credential-stealer indicators"
        platform = "Windows"
        target = "PE"
        family = "RustyStealer"
        severity = "high"
    strings:
        $f1 = "RustyStealer" ascii wide nocase
        $s1 = "Login Data" ascii wide
        $s2 = "Cookies" ascii wide
        $s3 = "Discord\\Local Storage\\leveldb" ascii wide
        $s4 = "wallet.dat" ascii wide
        $api1 = "CryptUnprotectData" ascii wide
        $api2 = "InternetReadFile" ascii wide
    condition:
        ($f1 and 1 of ($api*)) or (2 of ($s*) and 1 of ($api*))
}
