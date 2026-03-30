rule Script_Target_JS_Obfuscated_Dropper
{
    meta:
        description = "JavaScript dropper with obfuscation and launcher behavior"
        platform = "Cross"
        target = "Script"
        family = "Generic.JS.Dropper"
        severity = "medium"
    strings:
        $j1 = "eval(" ascii nocase
        $j2 = "String.fromCharCode" ascii nocase
        $j3 = "WScript.Shell" ascii nocase
        $j4 = "ActiveXObject" ascii nocase
        $j5 = "cmd.exe /c" ascii nocase
        $j6 = "powershell -" ascii nocase
    condition:
        3 of ($j*)
}
