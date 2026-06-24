namespace TqkLibrary.VpnClient.Tinc.Meta.Enums
{
    /// <summary>
    /// tinc meta-connection request codes (the leading integer of each meta line). Values match tinc's
    /// <c>request_t</c> enum (protocol.h). Application records over SPTPS carry these lines; the type byte of the
    /// SPTPS record is an opaque application type (&lt; 128), the request code is the first field of the line itself.
    /// </summary>
    public enum TincRequestType
    {
        Id = 0,
        MetaKey = 1,
        Challenge = 2,
        ChalReply = 3,
        Ack = 4,
        Status = 5,
        Error = 6,
        TermReq = 7,
        Ping = 8,
        Pong = 9,
        AddSubnet = 10,
        DelSubnet = 11,
        AddEdge = 12,
        DelEdge = 13,
        KeyChanged = 14,
        ReqKey = 15,
        AnsKey = 16,
        Packet = 17,
        Control = 18,
        ReqPubkey = 19,
        AnsPubkey = 20,
        SptpsPacket = 21,
        UdpInfo = 22,
        MtuInfo = 23,
    }
}
