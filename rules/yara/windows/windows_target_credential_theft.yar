rule Windows_Target_Credential_Theft
{
    meta:
        description = "Credential theft API and artifact combinations"
        platform = "Windows"
        target = "PE"
        family = "Generic.Stealer"
        severity = "medium"
    strings:
        $api1 = "CryptUnprotectData" ascii wide
        $api2 = "CredEnumerateW" ascii wide
        $api3 = "LogonUserW" ascii wide
        $db1 = "Login Data" ascii wide
        $db2 = "Web Data" ascii wide
        $db3 = "Cookies" ascii wide
    condition:
        (2 of ($api*)) or (1 of ($api*) and 2 of ($db*))
}
