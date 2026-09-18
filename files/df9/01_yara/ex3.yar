rule EX3_Nightjar_Loader
{
    strings:
        $marker = "NJ-CAMPAIGN-0x5A" ascii wide
        $web    = "New-Object Net.WebClient"
        $b64    = "FromBase64String"
    condition:
        $marker or $web or $b64
}
