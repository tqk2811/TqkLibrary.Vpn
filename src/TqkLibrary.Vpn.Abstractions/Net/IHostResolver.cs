using System.Net;

namespace TqkLibrary.Vpn.Abstractions.Net
{
    /// <summary>
    /// Resolves a VPN server host (name or IP literal) to a single <see cref="IPAddress"/> for the outer transport,
    /// honouring an <see cref="AddressFamilyPreference"/>. A seam (instance behind an interface) so drivers can be
    /// unit-tested with a fake resolver and no DNS — the default is <see cref="DnsHostResolver"/>.
    /// </summary>
    public interface IHostResolver
    {
        /// <summary>
        /// Resolves <paramref name="host"/> to one address. An IP literal is returned verbatim; a name is looked up and
        /// reduced to one address by <paramref name="preference"/> (preferred family first, the other as fallback).
        /// Throws when the host cannot be resolved to any address.
        /// </summary>
        Task<IPAddress> ResolveAsync(string host, AddressFamilyPreference preference = AddressFamilyPreference.Auto, CancellationToken cancellationToken = default);
    }
}
