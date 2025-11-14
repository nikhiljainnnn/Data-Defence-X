
rule Memory_Injection_Indicators
{
    meta:
        description = "Detects memory injection techniques"
        severity = "critical"
        author = "DataDefenceX"
    
    strings:
        $virtualalloc = "VirtualAlloc" nocase
        $virtualprotect = "VirtualProtect" nocase
        $writeprocessmemory = "WriteProcessMemory" nocase
        $createremotethread = "CreateRemoteThread" nocase
        $ntunmapviewofsection = "NtUnmapViewOfSection" nocase
        $shellcode_nop = {90 90 90 90 90 90 90 90 90 90}  // NOP sled (10+ bytes)
        $shellcode_loop = {EB FE}  // Infinite loop (JMP -2)
    
    condition:
        (2 of ($virtualalloc, $virtualprotect, $writeprocessmemory, $createremotethread)) or
        ($ntunmapviewofsection and $virtualalloc) or
        ($shellcode_nop or $shellcode_loop)
}
