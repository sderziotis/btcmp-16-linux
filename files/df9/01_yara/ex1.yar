rule EX1_Campaign_Marker
{
    strings:
        $m = "NJ-CAMPAIGN-0x5A" ascii wide
    condition:
        $m
}
