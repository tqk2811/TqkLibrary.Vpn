using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Framing.Enums;
using TqkLibrary.VpnClient.Ppp.Interfaces;

namespace TqkLibrary.VpnClient.Ppp
{
    /// <summary>
    /// Drives a PPP session over an <see cref="IPppFrameChannel"/>: runs LCP, an optional authentication phase
    /// (e.g. MS-CHAPv2 over CHAP), then IPCP; demultiplexes inbound frames by protocol field and exposes an
    /// <see cref="IPacketChannel"/> once the link is up.
    /// </summary>
    public sealed class PppEngine
    {
        readonly IPppFrameChannel _channel;
        readonly LcpNegotiator _lcp;
        readonly IpcpNegotiator _ipcp;
        readonly Ipv6cpNegotiator? _ipv6cp;
        readonly PppPacketChannel _packetChannel;
        readonly IPppAuthenticator? _authenticator;
        readonly object _sync = new();

        /// <summary>
        /// Creates an engine. <paramref name="localAddress"/> is the IP we request (0.0.0.0 for a client).
        /// Pass <paramref name="assignPeerAddress"/> to act as the server. Pass <paramref name="authenticator"/>
        /// to satisfy a server that demands authentication. Set <paramref name="enableIpv6"/> to also run IPV6CP
        /// (RFC 5072) alongside IPCP: it negotiates an Interface-Identifier → link-local fe80::/64 address without
        /// affecting the IPv4 link-up (IPCP stays the trigger for <see cref="LinkUp"/>). <paramref name="interfaceId"/>
        /// is the 8-byte identifier we request (default: derived from <paramref name="magic"/>);
        /// <paramref name="assignPeerInterfaceId"/> forces one onto the peer when acting as a server.
        /// </summary>
        public PppEngine(
            IPppFrameChannel channel,
            uint magic,
            IPAddress localAddress,
            IPAddress? assignPeerAddress = null,
            IPAddress? assignPeerDns = null,
            IPppAuthenticator? authenticator = null,
            int mtu = 1400,
            bool enableIpv6 = false,
            byte[]? interfaceId = null,
            byte[]? assignPeerInterfaceId = null)
        {
            _channel = channel;
            _channel.FrameReceived += OnFrame;
            _authenticator = authenticator;
            _lcp = new LcpNegotiator(p => SendControl(PppProtocol.Lcp, p), magic);
            _ipcp = new IpcpNegotiator(p => SendControl(PppProtocol.Ipcp, p), localAddress, assignPeerAddress, assignPeerDns);
            _packetChannel = new PppPacketChannel(SendIpAsync, mtu);
            _lcp.Opened += OnLcpOpened;
            _ipcp.Opened += OnIpcpOpened;
            if (enableIpv6)
            {
                _ipv6cp = new Ipv6cpNegotiator(p => SendControl(PppProtocol.Ipv6cp, p), interfaceId ?? DeriveInterfaceId(magic), assignPeerInterfaceId);
                _ipv6cp.Opened += OnIpv6cpOpened;
            }
        }

        /// <summary>Raised once IPCP is open and the link can carry IPv4 traffic.</summary>
        public event Action? LinkUp;

        /// <summary>Raised once IPV6CP is open and a link-local IPv6 address has been negotiated (only when IPv6 is enabled).</summary>
        public event Action? Ipv6Up;

        /// <summary>Raised when authentication succeeds.</summary>
        public event Action? AuthSucceeded;

        /// <summary>Raised when authentication fails.</summary>
        public event Action? AuthFailed;

        /// <summary>The L3 channel for this session (valid after <see cref="LinkUp"/>).</summary>
        public IPacketChannel PacketChannel => _packetChannel;

        /// <summary>Our negotiated IP address.</summary>
        public IPAddress AssignedAddress => _ipcp.AssignedAddress;

        /// <summary>DNS server learned via IPCP, if any.</summary>
        public IPAddress? AssignedDns => _ipcp.AssignedDns;

        /// <summary>Our negotiated link-local IPv6 address (fe80::/64 + Interface-Identifier), or null if IPv6 is not enabled.</summary>
        public IPAddress? AssignedAddressV6 => _ipv6cp?.LinkLocalAddress;

        /// <summary>True once the link is up (IPCP opened).</summary>
        public bool IsLinkUp { get; private set; }

        /// <summary>True once IPV6CP has opened and a link-local IPv6 address is available.</summary>
        public bool IsIpv6Up { get; private set; }

        /// <summary>True once authentication has succeeded (or none was required).</summary>
        public bool IsAuthenticated { get; private set; }

        /// <summary>Begins negotiation (LCP first).</summary>
        public void Start()
        {
            lock (_sync) _lcp.Start();
        }

        void OnLcpOpened()
        {
            if (_lcp.RequiresMsChapV2 && _authenticator != null)
                return; // wait for the server's CHAP Challenge; the network layer starts after auth succeeds.

            IsAuthenticated = true; // no auth required
            StartNetworkLayer();
        }

        // Starts the network-control protocols once the link (and any auth) is up: IPCP always, IPV6CP when enabled.
        void StartNetworkLayer()
        {
            _ipcp.Start();
            _ipv6cp?.Start();
        }

        void OnIpcpOpened()
        {
            IsLinkUp = true;
            LinkUp?.Invoke();
        }

        void OnIpv6cpOpened()
        {
            IsIpv6Up = true;
            Ipv6Up?.Invoke();
        }

        void HandleAuth(ReadOnlySpan<byte> packet)
        {
            PppAuthStatus status = _authenticator!.Handle(packet, out byte[]? response);
            if (response != null)
                SendControl(PppProtocol.Chap, response);

            switch (status)
            {
                case PppAuthStatus.Success:
                    IsAuthenticated = true;
                    AuthSucceeded?.Invoke();
                    StartNetworkLayer();
                    break;
                case PppAuthStatus.Failure:
                    AuthFailed?.Invoke();
                    break;
            }
        }

        void OnFrame(ReadOnlyMemory<byte> frame)
        {
            ReadOnlySpan<byte> span = frame.Span;
            int offset = 0;
            if (span.Length >= 2 && span[0] == 0xFF && span[1] == 0x03) offset = 2; // skip Address/Control
            if (span.Length < offset + 2) return;

            ushort proto = (ushort)((span[offset] << 8) | span[offset + 1]);
            ReadOnlyMemory<byte> info = frame.Slice(offset + 2);
            lock (_sync)
            {
                switch ((PppProtocol)proto)
                {
                    case PppProtocol.Lcp: _lcp.HandlePacket(info.Span); break;
                    case PppProtocol.Chap:
                        if (_authenticator != null) HandleAuth(info.Span);
                        break;
                    case PppProtocol.Ipcp: _ipcp.HandlePacket(info.Span); break;
                    case PppProtocol.Ipv6cp: _ipv6cp?.HandlePacket(info.Span); break;
                    case PppProtocol.Ip: _packetChannel.RaiseInbound(info); break;
                }
            }
        }

        void SendControl(PppProtocol proto, byte[] payload) => _ = _channel.SendAsync(BuildFrame((ushort)proto, payload));

        ValueTask SendIpAsync(ReadOnlyMemory<byte> ipPacket) => _channel.SendAsync(BuildFrame((ushort)PppProtocol.Ip, ipPacket.Span));

        // A deterministic, non-zero, locally-administered 8-byte Interface-Identifier derived from the PPP magic
        // number (EUI-64 layout with the fffe fill). Servers usually Nak it with their own value anyway.
        static byte[] DeriveInterfaceId(uint magic) => new byte[]
        {
            0x02,                                                        // U/L bit set (locally administered), unicast
            (byte)(magic >> 24), (byte)(magic >> 16), (byte)(magic >> 8),
            0xFF, 0xFE,                                                  // EUI-64 fill
            (byte)magic, 0x01,                                          // non-zero tail
        };

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
