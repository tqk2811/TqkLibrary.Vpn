using System.Net;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier.Transport
{
    /// <summary>
    /// Connects the UDP transport a ZeroTier node rides to its upstream node / controller — one datagram is one VL1
    /// packet (HELLO / OK / NETWORK_CONFIG_REQUEST / EXT_FRAME), so there is never any framing. The connection resolves
    /// the endpoint then asks the factory for a transport to it; the production factory opens a real UDP socket, an
    /// in-process factory returns a loopback so the whole driver can be driven offline. Mirrors
    /// <c>IN2nTransportFactory</c> / <c>INebulaTransportFactory</c>.
    /// </summary>
    public interface IZeroTierTransportFactory
    {
        /// <summary>
        /// Connects a transport to <paramref name="remote"/> (the ZeroTier node / controller) and returns it (with its
        /// inbound dispatch and the optional receive pump). The pump, when present, must be run by the caller on a task
        /// tied to the attempt lifetime.
        /// </summary>
        Task<ZeroTierTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
