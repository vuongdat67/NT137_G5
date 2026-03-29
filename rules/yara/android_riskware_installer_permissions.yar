rule Android_Riskware_Installer_Permissions
{
    meta:
        description = "Android installer/riskware permission combination"
        severity = "medium"
    strings:
        $p1 = "android.permission.REQUEST_INSTALL_PACKAGES" ascii wide
        $p2 = "android.permission.MANAGE_EXTERNAL_STORAGE" ascii wide
        $p3 = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
        $p4 = "android.permission.WRITE_EXTERNAL_STORAGE" ascii wide
    condition:
        2 of ($p*)
}
