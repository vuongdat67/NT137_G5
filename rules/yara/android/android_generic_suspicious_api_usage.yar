rule Android_Suspicious_API_Usage_Generic
{
    meta:
        description = "Generic Android suspicious API usage indicators"
        severity = "medium"
    strings:
        $a1 = "Landroid/telephony/SmsManager;->sendTextMessage" ascii
        $a2 = "Landroid/telephony/TelephonyManager;->getDeviceId" ascii
        $a3 = "Landroid/accessibilityservice/AccessibilityService;" ascii
        $a4 = "Ljava/lang/Runtime;->exec" ascii
        $a5 = "Ldalvik/system/DexClassLoader;" ascii
        $a6 = "Landroid/webkit/WebView;->addJavascriptInterface" ascii
        $a7 = "android.permission.REQUEST_INSTALL_PACKAGES" ascii wide
        $a8 = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
    condition:
        2 of ($a*)
}
