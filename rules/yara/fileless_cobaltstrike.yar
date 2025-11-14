
rule CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon indicators"
        severity = "critical"
        author = "DataDefenceX"
    
    strings:
        $beacon1 = "beacon.dll" nocase
        $beacon2 = "ReflectiveLoader" nocase
        $beacon3 = "beacon.x64.dll" nocase
        $malleable = "Malleable C2" nocase
        $sleep_mask = "sleep_mask" nocase
    
    condition:
        2 of them
}
