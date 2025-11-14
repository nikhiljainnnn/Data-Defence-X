
rule Fileless_WMI_Execution
{
    meta:
        description = "Detects WMI-based fileless malware execution"
        severity = "high"
        author = "DataDefenceX"
    
    strings:
        $wmi1 = "wmic" nocase
        $wmi2 = "winmgmts" nocase
        $process = "process call create" nocase
        $cmd = "cmd.exe /c" nocase
    
    condition:
        ($wmi1 or $wmi2) and $process and $cmd
}
