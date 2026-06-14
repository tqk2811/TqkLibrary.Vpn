namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// Carries one OpenVPN packet (the bytes after any TCP length prefix) per send/receive. The driver implements this
    /// over UDP (one datagram = one packet) or TCP (stripping/adding the 16-bit length prefix so the boundary is still
    /// one packet); an in-process pair implements it for tests. <see cref="OpenVpnControlChannel"/> sits on top.
    /// </summary>
    public interface IOpenVpnTransport
    {
        /// <summary>Sends one OpenVPN packet (control or data) as a single unit.</summary>
        Task SendAsync(ReadOnlyMemory<byte> packet);

        /// <summary>Raised for each inbound OpenVPN packet.</summary>
        event Action<ReadOnlyMemory<byte>>? DatagramReceived;
    }
}
