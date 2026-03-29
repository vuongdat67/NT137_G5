rule Android_Dangerous_Permissions
{
    meta:
        description = "Android dangerous permission combination"
        severity = "high"
    strings:
        $p1 = "android.permission.READ_SMS" ascii wide
        $p2 = "android.permission.SEND_SMS" ascii wide
        $p3 = "android.permission.RECEIVE_SMS" ascii wide
        $p4 = "android.permission.RECEIVE_BOOT_COMPLETED" ascii wide
        $p5 = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
        $p6 = "android.permission.READ_CONTACTS" ascii wide
        $p7 = "android.permission.RECORD_AUDIO" ascii wide
        $p8 = "android.permission.ACCESS_FINE_LOCATION" ascii wide
    condition:
        2 of ($p*)
}
