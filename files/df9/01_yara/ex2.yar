rule EX2_Campaign_Marker
{
    strings:
        $m = "NJ-CAMPAIGN-0x5A" ascii wide
        any of them
}
