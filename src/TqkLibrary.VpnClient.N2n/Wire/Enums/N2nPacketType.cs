namespace TqkLibrary.VpnClient.N2n.Wire.Enums
{
    /// <summary>
    /// n2n v3 message / packet-class type (<c>n2n_pc_t</c>), carried in the low 5 bits of the common header's 16-bit
    /// <c>flags</c> field (mask <see cref="N2nFlags.TypeMask"/> = 0x001f). These select which message body follows the
    /// 24-byte common header.
    /// </summary>
    public enum N2nPacketType : byte
    {
        /// <summary>Liveness ping (n2n_ping).</summary>
        Ping = 0,
        /// <summary>Edge↔edge registration / P2P hole-punch (n2n_register).</summary>
        Register = 1,
        /// <summary>Edge↔edge deregistration (n2n_deregister).</summary>
        Deregister = 2,
        /// <summary>Encapsulated L2 data frame (n2n_packet).</summary>
        Packet = 3,
        /// <summary>Acknowledge an edge↔edge REGISTER (n2n_register_ack).</summary>
        RegisterAck = 4,
        /// <summary>Edge → supernode registration (n2n_register_super).</summary>
        RegisterSuper = 5,
        /// <summary>Edge → supernode unregistration (n2n_unregister_super).</summary>
        UnregisterSuper = 6,
        /// <summary>Supernode → edge registration acknowledgement (n2n_register_super_ack).</summary>
        RegisterSuperAck = 7,
        /// <summary>Supernode → edge registration refusal (n2n_register_super_nak).</summary>
        RegisterSuperNak = 8,
        /// <summary>Supernode federation message (n2n_federation).</summary>
        Federation = 9,
        /// <summary>Supernode → edge peer information for P2P setup (n2n_peer_info).</summary>
        PeerInfo = 10,
        /// <summary>Edge → supernode query for a peer's socket (n2n_query_peer).</summary>
        QueryPeer = 11,
        /// <summary>Supernode → edge request to re-register (n2n_re_register_super).</summary>
        ReRegisterSuper = 12,
    }
}
