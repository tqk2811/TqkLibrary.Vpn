namespace TqkLibrary.VpnClient.ZeroTier.Vl1.Enums
{
    /// <summary>
    /// VL1 packet verb — the low 5 bits of the verb byte (the first plaintext byte of the payload). The verb names a
    /// protocol operation; only the subset this client needs is enumerated.
    /// </summary>
    public enum Vl1Verb : byte
    {
        /// <summary>No operation / keepalive.</summary>
        Nop = 0x00,

        /// <summary>Announce identity and negotiate a session (the VL1 handshake). Always Poly1305-only (unencrypted).</summary>
        Hello = 0x01,

        /// <summary>Acknowledgement / error reply to a previous packet.</summary>
        Error = 0x02,

        /// <summary>Successful reply to a request (e.g. the OK to a HELLO).</summary>
        Ok = 0x03,

        /// <summary>Query the identity behind an address.</summary>
        WhoIs = 0x04,

        /// <summary>Path/rendezvous assistance for NAT traversal.</summary>
        Rendezvous = 0x05,

        /// <summary>A VL2 Ethernet frame (unicast) carried over VL1.</summary>
        Frame = 0x06,

        /// <summary>A VL2 Ethernet frame with extended addressing / per-frame metadata.</summary>
        ExtFrame = 0x07,

        /// <summary>Liveness check echoed back by the peer (keepalive).</summary>
        Echo = 0x08,

        /// <summary>Attach network credentials (certificate of membership, capabilities, tags) to a peer.</summary>
        NetworkCredentials = 0x0A,

        /// <summary>Ask the network controller for this node's configuration on a network (VL2 join).</summary>
        NetworkConfigRequest = 0x0B,

        /// <summary>A network configuration pushed by the controller (the controller's reply to a request).</summary>
        NetworkConfig = 0x0C,

        /// <summary>Multicast frame.</summary>
        MulticastFrame = 0x0E,
    }
}
