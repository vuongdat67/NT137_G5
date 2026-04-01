rule Android_Family_SpyNote
{
    meta:
        description = "SpyNote Android RAT markers"
        platform = "Android"
        target = "APK"
        family = "SpyNote"
        severity = "high"
    strings:
        $k1 = "spynote" ascii wide nocase
        $k2 = "spymax" ascii wide nocase
        $p1 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide
        $p2 = "android.permission.RECEIVE_BOOT_COMPLETED" ascii wide
        $a1 = "AccessibilityService" ascii wide
        $a2 = "performGlobalAction" ascii wide
        $c1 = "Landroid/media/MediaRecorder;" ascii
    condition:
        ($k1 or $k2) and (1 of ($p*) and 1 of ($a*, $c1))
}
