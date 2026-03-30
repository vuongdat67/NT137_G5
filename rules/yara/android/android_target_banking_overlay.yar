rule Android_Target_Banking_Overlay
{
    meta:
        description = "Banking overlay and accessibility abuse indicators"
        platform = "Android"
        target = "APK"
        family = "Generic.Banker"
        severity = "high"
    strings:
        $perm1 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide
        $perm2 = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
        $perm3 = "android.permission.RECEIVE_BOOT_COMPLETED" ascii wide
        $kw1 = "AccessibilityService" ascii wide
        $kw2 = "TYPE_APPLICATION_OVERLAY" ascii wide
        $kw3 = "performGlobalAction" ascii wide
    condition:
        (2 of ($perm*) and 2 of ($kw*))
}
