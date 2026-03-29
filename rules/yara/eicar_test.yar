rule EICAR_Test_String
{
    meta:
        description = "Detects EICAR antivirus test file"
        severity = "low"
    strings:
        $eicar_marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar_marker
}
