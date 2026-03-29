rule Windows_Process_Injection_APIs
{
    meta:
        description = "Common process injection API tuple"
        severity = "high"
    strings:
        $a1 = "VirtualAlloc" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "NtCreateThreadEx" ascii wide
    condition:
        ($a1 and $a2 and ($a3 or $a4))
}
