using System.Net;

namespace TqkLibrary.VpnClient.Drivers.Tinc.Transport
{
    /// <summary>
    /// Connects the two transports a tinc session rides: the <b>TCP meta-connection</b> (port 655 — ID, the SPTPS
    /// handshake, ACK, ADD_SUBNET/ADD_EDGE and the data-plane REQ_KEY/ANS_KEY key exchange) and the <b>UDP data plane</b>
    /// (the same endpoint — SPTPS data datagrams). The production factory opens real sockets; an in-process factory
    /// returns loopbacks so the whole driver can be driven offline. Mirrors <c>INebulaTransportFactory</c> but yields a
    /// pair (stream + datagram) because tinc, unlike Nebula, needs both.
    /// </summary>
    public interface ITincTransportFactory
    {
        /// <summary>
        /// Connects a TCP meta-connection and a UDP data socket to <paramref name="remote"/> and returns them (with the
        /// optional UDP receive pump the caller runs for the attempt lifetime).
        /// </summary>
        Task<TincTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
