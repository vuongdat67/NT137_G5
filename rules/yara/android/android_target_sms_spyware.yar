rule Android_Target_SMS_Spyware
{
    meta:
        description = "SMS spyware behavior via permission and API pairs"
        platform = "Android"
        target = "APK"
        family = "Generic.SMSSpyware"
        severity = "high"
    strings:
        $perm1 = "android.permission.READ_SMS" ascii wide
        $perm2 = "android.permission.SEND_SMS" ascii wide
        $perm3 = "android.permission.RECEIVE_SMS" ascii wide
        $api1 = "Landroid/telephony/SmsManager;->sendTextMessage" ascii
        $api2 = "Landroid/provider/Telephony$Sms" ascii
        $api3 = "content://sms" ascii wide
    condition:
        (2 of ($perm*) and 1 of ($api*))
}
