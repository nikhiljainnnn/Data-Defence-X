
rule Fileless_Rundll32_Suspicious
{
    meta:
        description = "Detects suspicious Rundll32 usage (common LOLBin for fileless)"
        severity = "medium"
        author = "DataDefenceX"
    
    strings:
        $rundll = "rundll32" nocase
        $suspicious1 = "javascript:" nocase
        $suspicious2 = "vbscript:" nocase
        $suspicious3 = "data:text/html" nocase
        $temp = /[Tt]emp/
    
    condition:
        $rundll and ($suspicious1 or $suspicious2 or $suspicious3 or $temp)
}
