using TqkLibrary.VpnClient.Abstractions.Net;

namespace TqkLibrary.VpnClient.Abstractions.Drivers.Models
{
    /// <summary>The remote VPN server address a driver connects to.</summary>
    public sealed class VpnEndpoint
    {
        /// <summary>Creates an endpoint from a host (name or IP literal) and port.</summary>
        public VpnEndpoint(string host, int port, AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto)
        {
            Host = host ?? throw new ArgumentNullException(nameof(host));
            Port = port;
            AddressFamilyPreference = addressFamilyPreference;
        }

        /// <summary>Server host name or IP literal.</summary>
        public string Host { get; }

        /// <summary>Server port (443 for SSTP, 500/4500 for L2TP/IPsec...).</summary>
        public int Port { get; }

        /// <summary>Which IP family to prefer for the outer transport when <see cref="Host"/> resolves to both.</summary>
        public AddressFamilyPreference AddressFamilyPreference { get; }
    }
}
