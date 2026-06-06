using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Ppp.Framing.Enums;
using TqkLibrary.Vpn.Ppp.Interfaces;

namespace TqkLibrary.Vpn.Ppp
{
    /// <summary>
    /// Drives a PPP session over an <see cref="IPppFrameChannel"/>: runs LCP, then IPCP, demultiplexes inbound
    /// frames by protocol field, and exposes an <see cref="IPacketChannel"/> once the link is up.
    /// (Authentication phase — MS-CHAPv2 over CHAP — is wired in a later step; the crypto already exists.)
    /// </summary>
    public sealed class PppEngine
    {
        readonly IPppFrameChannel _channel;
        readonly LcpNegotiator _lcp;
        readonly IpcpNegotiator _ipcp;
        readonly PppPacketChannel _packetChannel;

        /// <summary>
        /// Creates an engine. <paramref name="localAddress"/> is the IP we request (0.0.0.0 for a client).
        /// Pass <paramref name="assignPeerAddress"/> to act as the server that assigns the peer an address.
        /// </summary>
        public PppEngine(
            IPppFrameChannel channel,
            uint magic,
            IPAddress localAddress,
            IPAddress? assignPeerAddress = null,
            IPAddress? assignPeerDns = null,
            int mtu = 1400)
        {
            _channel = channel;
            _channel.FrameReceived += OnFrame;
            _lcp = new LcpNegotiator(p => SendControl(PppProtocol.Lcp, p), magic);
            _ipcp = new IpcpNegotiator(p => SendControl(PppProtocol.Ipcp, p), localAddress, assignPeerAddress, assignPeerDns);
            _packetChannel = new PppPacketChannel(SendIpAsync, mtu);
            _lcp.Opened += OnLcpOpened;
            _ipcp.Opened += OnIpcpOpened;
        }

        /// <summary>Raised once IPCP is open and the link can carry IP traffic.</summary>
        public event Action? LinkUp;

        /// <summary>The L3 channel for this session (valid after <see cref="LinkUp"/>).</summary>
        public IPacketChannel PacketChannel => _packetChannel;

        /// <summary>Our negotiated IP address.</summary>
        public IPAddress AssignedAddress => _ipcp.AssignedAddress;

        /// <summary>DNS server learned via IPCP, if any.</summary>
        public IPAddress? AssignedDns => _ipcp.AssignedDns;

        /// <summary>True once the link is up (IPCP opened).</summary>
        public bool IsLinkUp { get; private set; }

        /// <summary>Begins negotiation (LCP first).</summary>
        public void Start() => _lcp.Start();

        void OnLcpOpened() => _ipcp.Start(); // TODO: insert the authentication phase here once CHAP packets are wired.

        void OnIpcpOpened()
        {
            IsLinkUp = true;
            LinkUp?.Invoke();
        }

        void OnFrame(ReadOnlyMemory<byte> frame)
        {
            ReadOnlySpan<byte> span = frame.Span;
            int offset = 0;
            if (span.Length >= 2 && span[0] == 0xFF && span[1] == 0x03) offset = 2; // skip Address/Control
            if (span.Length < offset + 2) return;

            ushort proto = (ushort)((span[offset] << 8) | span[offset + 1]);
            ReadOnlyMemory<byte> info = frame.Slice(offset + 2);
            switch ((PppProtocol)proto)
            {
                case PppProtocol.Lcp: _lcp.HandlePacket(info.Span); break;
                case PppProtocol.Ipcp: _ipcp.HandlePacket(info.Span); break;
                case PppProtocol.Ip: _packetChannel.RaiseInbound(info); break;
            }
        }

        void SendControl(PppProtocol proto, byte[] payload) => _ = _channel.SendAsync(BuildFrame((ushort)proto, payload));

        ValueTask SendIpAsync(ReadOnlyMemory<byte> ipPacket) => _channel.SendAsync(BuildFrame((ushort)PppProtocol.Ip, ipPacket.Span));

        static byte[] BuildFrame(ushort proto, ReadOnlySpan<byte> payload)
        {
            byte[] frame = new byte[4 + payload.Length];
            frame[0] = 0xFF;
            frame[1] = 0x03;
            frame[2] = (byte)(proto >> 8);
            frame[3] = (byte)proto;
            payload.CopyTo(frame.AsSpan(4));
            return frame;
        }
    }
}
