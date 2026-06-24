namespace TqkLibrary.VpnClient.N2n.Wire.Enums
{
    /// <summary>
    /// Bit masks for the 16-bit <c>flags</c> field of the n2n v3 common header. The low 5 bits hold the
    /// <see cref="N2nPacketType"/> (<see cref="TypeMask"/>); the high bits are independent flags that the receiver tests
    /// to decide whether optional sections (a socket, extra options) are present and the packet's direction.
    /// </summary>
    [Flags]
    public enum N2nFlags : ushort
    {
        /// <summary>No flag bits set.</summary>
        None = 0x0000,
        /// <summary>Mask selecting the packet type (<see cref="N2nPacketType"/>) in the low 5 bits.</summary>
        TypeMask = 0x001f,
        /// <summary>Packet originates from a supernode (set on supernode→edge replies).</summary>
        FromSupernode = 0x0020,
        /// <summary>An encoded <c>n2n_sock_t</c> is present in the body at the position the message defines.</summary>
        Socket = 0x0040,
        /// <summary>Trailing options block is present after the body.</summary>
        Options = 0x0080,
    }
}
