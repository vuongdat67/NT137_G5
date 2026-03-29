rule Packed_UPX_Heuristic
{
    meta:
        description = "UPX section markers in PE"
        severity = "medium"
    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*))
}
