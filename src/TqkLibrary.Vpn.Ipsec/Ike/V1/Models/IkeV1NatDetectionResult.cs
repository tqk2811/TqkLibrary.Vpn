namespace TqkLibrary.Vpn.Ipsec.Ike.V1.Models
{
    /// <summary>
    /// The NAT-Traversal verdict read from the responder's MM4 NAT-D payloads (RFC 3947): whether the gateway sent
    /// any NAT-D at all, and — if so — whether it observed a NAT in front of us (the initiator) or in front of itself.
    /// </summary>
    public sealed class IkeV1NatDetectionResult
    {
        /// <summary>Creates a verdict from the three observed facts.</summary>
        public IkeV1NatDetectionResult(bool serverSentNatD, bool localBehindNat, bool remoteBehindNat)
        {
            ServerSentNatD = serverSentNatD;
            LocalBehindNat = localBehindNat;
            RemoteBehindNat = remoteBehindNat;
        }

        /// <summary>True if the responder included NAT-D payloads in MM4 (i.e. it supports NAT-T at all).</summary>
        public bool ServerSentNatD { get; }

        /// <summary>True if the gateway saw our source address/port translated — there is a NAT in front of us.</summary>
        public bool LocalBehindNat { get; }

        /// <summary>True if our hash of the gateway's own address did not match — there is a NAT in front of it.</summary>
        public bool RemoteBehindNat { get; }

        /// <summary>
        /// True when an honest handshake should float to UDP/4500 (real NAT in the path): the gateway sent NAT-D and
        /// detected a NAT in front of us. Otherwise the gateway expects native ESP (no NAT) or does not do NAT-T.
        /// </summary>
        public bool ShouldFloatToNatT => ServerSentNatD && LocalBehindNat;
    }
}
