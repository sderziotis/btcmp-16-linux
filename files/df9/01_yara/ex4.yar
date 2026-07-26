rule EX4_PE_Payload
{
    strings:
        $imp = "CreateRemoteThread"
    condition:
        uint16(0) == 0x4D5A and $imp
}
