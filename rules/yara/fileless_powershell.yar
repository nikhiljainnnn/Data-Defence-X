
rule Fileless_PowerShell_EncodedCommand
{
    meta:
        description = "Detects PowerShell with encoded commands (common in fileless attacks)"
        severity = "high"
        author = "DataDefenceX"
        date = "2025-01-01"
    
    strings:
        $ps1 = "powershell" nocase
        $encoded = "-encodedcommand" nocase
        $base64 = /[A-Za-z0-9+\/]{100,}={0,2}/
        $bypass = "-executionpolicy" nocase
        $hidden = "-windowstyle hidden" nocase
    
    condition:
        $ps1 and ($encoded or ($bypass and $hidden)) or ($ps1 and $base64)
}
