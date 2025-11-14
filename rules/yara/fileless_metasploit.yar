
rule Metasploit_Payload
{
    meta:
        description = "Detects Metasploit payload indicators"
        severity = "high"
        author = "DataDefenceX"
    
    strings:
        $msf1 = "meterpreter" nocase
        $msf2 = "metsrv" nocase
        $msf3 = "stdapi" nocase
        $msf4 = "priv" nocase
    
    condition:
        2 of them
}
