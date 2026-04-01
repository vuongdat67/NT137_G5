rule Windows_Family_Emotet
{
    meta:
        description = "Emotet-like loader/network and injection markers"
        platform = "Windows"
        target = "PE"
        family = "Emotet"
        severity = "high"
    strings:
        $k1 = "Emotet" ascii wide nocase
        $k2 = "epoch" ascii wide nocase
        $api1 = "WinHttpOpen" ascii wide
        $api2 = "HttpSendRequestW" ascii wide
        $api3 = "URLDownloadToFileW" ascii wide
        $inj1 = "CreateRemoteThread" ascii wide
    condition:
        uint16(0) == 0x5A4D and (($k1 and 1 of ($api*)) or ($k2 and $inj1 and 1 of ($api*)))
}

rule Windows_Family_RemcosRAT
{
    meta:
        description = "RemcosRAT command-and-control and surveillance markers"
        platform = "Windows"
        target = "PE"
        family = "RemcosRAT"
        severity = "high"
    strings:
        $k1 = "Remcos" ascii wide nocase
        $k2 = "remcos v" ascii wide nocase
        $c1 = "SetWindowsHookEx" ascii wide
        $c2 = "GetForegroundWindow" ascii wide
        $c3 = "WSAStartup" ascii wide
        $c4 = "CreateMutex" ascii wide
    condition:
        uint16(0) == 0x5A4D and (($k1 or $k2) and 2 of ($c*))
}

rule Windows_Family_AgentTesla
{
    meta:
        description = "AgentTesla credential theft and exfiltration markers"
        platform = "Windows"
        target = "PE"
        family = "AgentTesla"
        severity = "high"
    strings:
        $k1 = "Agent Tesla" ascii wide nocase
        $k2 = "agenttesla" ascii wide nocase
        $e1 = "smtp.gmail.com" ascii wide nocase
        $e2 = "mail.smtp" ascii wide nocase
        $e3 = "ftp://" ascii wide
        $s1 = "GetAsyncKeyState" ascii wide
        $s2 = "CryptUnprotectData" ascii wide
    condition:
        uint16(0) == 0x5A4D and ((1 of ($k*) and 1 of ($e*) and 1 of ($s*)) or (2 of ($e*) and 1 of ($s*)))
}

rule Windows_Family_AsyncRAT
{
    meta:
        description = "AsyncRAT remote access and crypto config markers"
        platform = "Windows"
        target = "PE"
        family = "AsyncRAT"
        severity = "high"
    strings:
        $k1 = "AsyncRAT" ascii wide nocase
        $k2 = "ClientSettings" ascii wide
        $n1 = "TcpClient" ascii wide
        $n2 = "Pastebin" ascii wide nocase
        $c1 = "AesCryptoServiceProvider" ascii wide
        $c2 = "Mutex" ascii wide
    condition:
        uint16(0) == 0x5A4D and (($k1 and 1 of ($n*) and 1 of ($c*)) or ($k2 and 2 of ($n*, $c*)))
}

rule Windows_Family_LokiBot
{
    meta:
        description = "LokiBot stealer indicators (credential DB + exfil path)"
        platform = "Windows"
        target = "PE"
        family = "LokiBot"
        severity = "high"
    strings:
        $k1 = "LokiBot" ascii wide nocase
        $d1 = "Login Data" ascii wide
        $d2 = "Web Data" ascii wide
        $d3 = "Cookies" ascii wide
        $e1 = "/fre.php" ascii wide nocase
        $e2 = "POST /" ascii wide
        $api1 = "CryptUnprotectData" ascii wide
    condition:
        uint16(0) == 0x5A4D and (($k1 and 1 of ($d*) and ($e1 or $api1)) or (2 of ($d*) and $api1 and 1 of ($e*)))
}

rule Windows_Family_Stealc
{
    meta:
        description = "Stealc stealer family markers"
        platform = "Windows"
        target = "PE"
        family = "Stealc"
        severity = "high"
    strings:
        $k1 = "stealc" ascii wide nocase
        $d1 = "Discord\\Local Storage\\leveldb" ascii wide
        $d2 = "wallet.dat" ascii wide
        $d3 = "Login Data" ascii wide
        $e1 = "/gate.php" ascii wide nocase
        $api1 = "CryptUnprotectData" ascii wide
    condition:
        uint16(0) == 0x5A4D and (($k1 and 1 of ($d*) and ($e1 or $api1)) or (2 of ($d*) and $api1))
}
