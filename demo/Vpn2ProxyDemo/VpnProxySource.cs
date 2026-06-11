using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.Vpn.IpStack.Tcp;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// An <see cref="IProxySource"/> that routes proxied traffic through a VPN tunnel's userspace IP stack
    /// (<see cref="TcpIpStack"/>). Plug it into a <c>TqkLibrary.Proxy.ProxyServer</c> so an HTTP/SOCKS proxy
    /// listening on localhost forwards its traffic out the VPN.
    /// <para>
    /// Supports SOCKS4/5 + HTTP/HTTPS CONNECT (TCP) and SOCKS5 UDP-ASSOCIATE (datagrams ride the stack's userspace
    /// UDP socket). IPv4-only. BIND is not offered: the stack is active-open only, and the private tunnel address
    /// is not routable from the internet, so an external peer could never dial in.
    /// </para>
    /// </summary>
    public sealed partial class VpnProxySource : IProxySource
    {
        readonly TcpIpStack _stack;

        /// <summary>Creates the source over a userspace TCP/IP stack already bound to a connected tunnel.</summary>
        public VpnProxySource(TcpIpStack stack)
        {
            _stack = stack ?? throw new ArgumentNullException(nameof(stack));
        }

        /// <inheritdoc/>
        public bool IsSupportUdp => true;

        /// <inheritdoc/>
        public bool IsSupportIpv6 => false;

        /// <inheritdoc/>
        public bool IsSupportBind => false;

        /// <inheritdoc/>
        public Task<IConnectSource> GetConnectSourceAsync(Guid tunnelId, CancellationToken cancellationToken = default)
            => Task.FromResult<IConnectSource>(new VpnConnectSource(_stack));

        /// <inheritdoc/>
        public Task<IBindSource> GetBindSourceAsync(Guid tunnelId, CancellationToken cancellationToken = default)
            => throw new NotSupportedException(
                "BIND is not supported over the VPN userspace stack: active-open only, and the private tunnel address is not routable from the internet.");

        /// <inheritdoc/>
        public Task<IUdpAssociateSource> GetUdpAssociateSourceAsync(Guid tunnelId, CancellationToken cancellationToken = default)
            => Task.FromResult<IUdpAssociateSource>(new VpnUdpAssociateSource(_stack));
    }
}
