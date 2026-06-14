namespace TqkLibrary.VpnClient.Ppp.Enums
{
    /// <summary>PPP control packet codes (RFC 1661 §5) shared by LCP, IPCP and other control protocols.</summary>
    public enum PppCode : byte
    {
        ConfigureRequest = 1,
        ConfigureAck = 2,
        ConfigureNak = 3,
        ConfigureReject = 4,
        TerminateRequest = 5,
        TerminateAck = 6,
        CodeReject = 7,

        /// <summary>LCP only.</summary>
        ProtocolReject = 8,

        /// <summary>LCP only.</summary>
        EchoRequest = 9,

        /// <summary>LCP only.</summary>
        EchoReply = 10,

        /// <summary>LCP only.</summary>
        DiscardRequest = 11,
    }
}
