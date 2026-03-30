rule Android_Family_Arsink
{
    meta:
        description = "Arsink family marker and suspicious installer behavior"
        platform = "Android"
        target = "APK"
        family = "Arsink"
        severity = "high"
    strings:
        $f1 = "Arsink" ascii wide nocase
        $p1 = "android.permission.REQUEST_INSTALL_PACKAGES" ascii wide
        $p2 = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
        $p3 = "android.permission.RECEIVE_BOOT_COMPLETED" ascii wide
        $i1 = "android.intent.action.BOOT_COMPLETED" ascii wide
        $i2 = "android.intent.action.PACKAGE_ADDED" ascii wide
    condition:
        ($f1 and 1 of ($p*)) or (2 of ($p*) and 1 of ($i*))
}
