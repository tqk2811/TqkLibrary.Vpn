using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.Vpn.Abstractions.Net
{
    /// <summary>
    /// The default <see cref="IHostResolver"/>: an IP literal passes through unchanged; a name is looked up via
    /// <see cref="Dns"/> and reduced to one address by <see cref="Select"/> (preferred family first, the other as
    /// fallback). The family-selection step is a pure static so it is unit-testable with literal address lists.
    /// </summary>
    public sealed class DnsHostResolver : IHostResolver
    {
        /// <summary>A shared stateless instance.</summary>
        public static readonly DnsHostResolver Default = new DnsHostResolver();

        /// <inheritdoc/>
        public async Task<IPAddress> ResolveAsync(string host, AddressFamilyPreference preference = AddressFamilyPreference.Auto, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(host)) throw new ArgumentException("Host must not be empty.", nameof(host));
            if (IPAddress.TryParse(host, out IPAddress? literal)) return literal; // explicit literal wins over preference
            cancellationToken.ThrowIfCancellationRequested();
#if NET6_0_OR_GREATER
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
#else
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
#endif
            IPAddress? chosen = Select(addresses, preference);
            if (chosen is null) throw new SocketException((int)SocketError.HostNotFound);
            return chosen;
        }

        /// <summary>
        /// Picks one address from <paramref name="addresses"/> by <paramref name="preference"/>: every address of the
        /// preferred family first (in order), then the other family as fallback. Returns <c>null</c> when the list is
        /// empty. Pure and side-effect-free — the testable core of <see cref="ResolveAsync"/>.
        /// </summary>
        public static IPAddress? Select(IReadOnlyList<IPAddress> addresses, AddressFamilyPreference preference)
        {
            if (addresses is null || addresses.Count == 0) return null;
            AddressFamily preferred = preference == AddressFamilyPreference.IPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            AddressFamily fallback = preferred == AddressFamily.InterNetwork ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            return FirstOf(addresses, preferred) ?? FirstOf(addresses, fallback);
        }

        static IPAddress? FirstOf(IReadOnlyList<IPAddress> addresses, AddressFamily family)
        {
            for (int i = 0; i < addresses.Count; i++)
                if (addresses[i].AddressFamily == family) return addresses[i];
            return null;
        }
    }
}
