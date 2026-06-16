namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums
{
    /// <summary>Configuration Payload (CP) types — what the CFG exchange is doing (RFC 7296 §3.15.1).</summary>
    public enum IkeConfigType : byte
    {
        /// <summary>The initiator asks for configuration (attribute values empty/length 0).</summary>
        Request = 1,

        /// <summary>The responder returns the assigned configuration.</summary>
        Reply = 2,

        /// <summary>Unsolicited push of configuration to the peer.</summary>
        Set = 3,

        /// <summary>Acknowledgement of a CFG_SET.</summary>
        Ack = 4,
    }
}
