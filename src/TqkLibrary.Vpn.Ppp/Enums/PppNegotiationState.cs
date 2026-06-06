namespace TqkLibrary.Vpn.Ppp.Enums
{
    /// <summary>Simplified state of a PPP option negotiator (subset of the RFC 1661 automaton).</summary>
    public enum PppNegotiationState
    {
        /// <summary>Not started.</summary>
        Closed = 0,

        /// <summary>Our Configure-Request has been sent; awaiting Ack/Nak/Reject and the peer's request.</summary>
        RequestSent = 1,

        /// <summary>Both directions acknowledged — the protocol is up.</summary>
        Opened = 2,
    }
}
