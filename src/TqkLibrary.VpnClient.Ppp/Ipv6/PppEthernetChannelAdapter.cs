using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Ppp.Ipv6
{
    /// <summary>
    /// Presents a PPP L3 <see cref="IPacketChannel"/> as an <see cref="IEthernetChannel"/> so the L3 IPv6 auto-configuration
    /// engine (<see cref="NdiscResolver"/> + <see cref="Ipv6AddressConfigurator"/>, which are written against an Ethernet
    /// port) can be reused unchanged over a PPP link (P1.1). A PPP link has no Ethernet layer: this adapter strips the
    /// 14-byte Ethernet header off every frame the engine sends and forwards the bare IPv6 packet to the channel
    /// (<see cref="IPacketChannel.WriteIpPacketAsync"/>), and raises <see cref="InboundFrame"/> with each bare inbound IP
    /// packet (both <see cref="NdiscResolver.HandleInboundFrame"/> and <see cref="Ipv6AddressConfigurator.HandleInboundFrame"/>
    /// already accept a bare IPv6 packet). The MAC it carries is synthetic — only the Source Link-Layer Address option of a
    /// Router Solicitation and the DHCPv6 DUID use it, both cosmetic on a point-to-point link; the SLAAC interface
    /// identifier comes from IPV6CP via <see cref="Ipv6AddressConfiguratorOptions.InterfaceIdentifierOverride"/>.
    /// <para>
    /// The adapter does not own <paramref name="inner"/> (the <see cref="PppEngine"/> owns it): disposing only detaches the
    /// inbound subscription, never the channel. Call <see cref="Start"/> after wiring <see cref="InboundFrame"/> handlers so
    /// no inbound packet is dropped before the engine is listening.
    /// </para>
    /// </summary>
    public sealed class PppEthernetChannelAdapter : IEthernetChannel
    {
        readonly IPacketChannel _inner;
        readonly byte[] _mac;
        int _started;
        bool _disposed;

        /// <summary>Wraps <paramref name="inner"/>, presenting <paramref name="mac"/> as this endpoint's link address.</summary>
        public PppEthernetChannelAdapter(IPacketChannel inner, MacAddress mac)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _mac = mac.ToArray();
        }

        /// <summary>Begins forwarding inbound IP packets as Ethernet frames; idempotent.</summary>
        public void Start()
        {
            if (Interlocked.Exchange(ref _started, 1) == 0 && !_disposed)
                _inner.InboundIpPacket += OnInboundIpPacket;
        }

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> LinkAddress => _mac;

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ethernet;

        /// <inheritdoc/>
        public int Mtu => _inner.Mtu;

        /// <inheritdoc/>
        public int MaxHeaderLength => EthernetFrame.HeaderLength;

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => false;   // point-to-point: the peer is the only next hop

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundFrame;

        /// <inheritdoc/>
        public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
        {
            if (_disposed || ethernetFrame.Length < EthernetFrame.HeaderLength)
                return default;
            // Strip the synthetic Ethernet header; the payload is the bare IPv6 packet the PPP channel carries as proto 0x0057.
            return _inner.WriteIpPacketAsync(EthernetFrame.Payload(ethernetFrame), cancellationToken);
        }

        void OnInboundIpPacket(ReadOnlyMemory<byte> ipPacket) => InboundFrame?.Invoke(ipPacket);

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            if (_disposed)
                return default;
            _disposed = true;
            if (Volatile.Read(ref _started) == 1)
                _inner.InboundIpPacket -= OnInboundIpPacket;
            return default;
        }
    }
}
