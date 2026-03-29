rule Suspicious_C2_Strings
{
    meta:
        description = "Generic suspicious C2 and persistence string markers"
        severity = "medium"
    strings:
        $u1 = /https?:\/\/[A-Za-z0-9\-\._]+\/[A-Za-z0-9\-\._\?=&]*/ ascii
        $m1 = /Global\\[A-Za-z0-9_\-]{3,}/ ascii wide
        $r1 = /HKEY_(LOCAL_MACHINE|CURRENT_USER)\\/ ascii wide
    condition:
        2 of ($u1, $m1, $r1)
}
