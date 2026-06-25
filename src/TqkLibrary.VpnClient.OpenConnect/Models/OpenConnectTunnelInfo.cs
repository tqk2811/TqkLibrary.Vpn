using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.OpenConnect.Enums;

namespace TqkLibrary.VpnClient.OpenConnect.Models
{
    /// <summary>
    /// The tunnel configuration an OpenConnect/ocserv gateway returns in the <c>X-CSTP-*</c> headers of the HTTP
    /// CONNECT response: the assigned address(es), netmask, DNS servers, split-include routes, MTU, and the DPD /
    /// keep-alive / rekey timers. <see cref="ToTunnelConfig"/> maps it onto the shared <see cref="TunnelConfig"/> the
    /// userspace stack consumes (CSTP assigns the IP in-band — <see cref="Enums.CstpPacketType"/> data rides L3 directly,
    /// no PPP).
    /// </summary>
    public sealed class OpenConnectTunnelInfo
    {
        /// <summary>The assigned IPv4 tunnel address (<c>X-CSTP-Address</c>), if any.</summary>
        public IPAddress? Address { get; set; }

        /// <summary>The assigned IPv6 tunnel address (<c>X-CSTP-Address-IP6</c>), if any.</summary>
        public IPAddress? AddressV6 { get; set; }

        /// <summary>The IPv4 netmask (<c>X-CSTP-Netmask</c>), used to derive the prefix length.</summary>
        public IPAddress? Netmask { get; set; }

        /// <summary>The IPv6 prefix length (<c>X-CSTP-Address-IP6</c> CIDR suffix); 64 when unset.</summary>
        public int PrefixLengthV6 { get; set; } = 64;

        /// <summary>Pushed DNS servers (<c>X-CSTP-DNS</c>, repeated).</summary>
        public List<IPAddress> DnsServers { get; } = new();

        /// <summary>Split-include routes as CIDR text (<c>X-CSTP-Split-Include</c>, repeated).</summary>
        public List<string> Routes { get; } = new();

        /// <summary>Tunnel MTU (<c>X-CSTP-MTU</c>, falling back to <c>X-CSTP-Base-MTU</c>); null when unset.</summary>
        public int? Mtu { get; set; }

        /// <summary>Dead-peer-detection interval in seconds (<c>X-CSTP-DPD</c>); null = DPD disabled.</summary>
        public int? Dpd { get; set; }

        /// <summary>Keep-alive interval in seconds (<c>X-CSTP-Keepalive</c>); null = disabled.</summary>
        public int? Keepalive { get; set; }

        /// <summary>The rekey method the server requested (<c>X-CSTP-Rekey-Method</c>: <c>ssl</c> / <c>new-tunnel</c> / <c>none</c>).</summary>
        public string? RekeyMethod { get; set; }

        /// <summary>The rekey period in seconds (<c>X-CSTP-Rekey-Time</c>); null when unset.</summary>
        public int? RekeyTime { get; set; }

        /// <summary>
        /// The parsed <see cref="OpenConnectRekeyMethod"/> the gateway requested (from <see cref="RekeyMethod"/>):
        /// <c>ssl</c> ⇒ <see cref="OpenConnectRekeyMethod.Ssl"/>, <c>new-tunnel</c> ⇒ <see cref="OpenConnectRekeyMethod.NewTunnel"/>,
        /// anything else (including <c>none</c> / unset / a zero <see cref="RekeyTime"/>) ⇒ <see cref="OpenConnectRekeyMethod.None"/>.
        /// </summary>
        public OpenConnectRekeyMethod ParsedRekeyMethod
        {
            get
            {
                if (!RekeyTime.HasValue || RekeyTime.Value <= 0 || string.IsNullOrEmpty(RekeyMethod))
                    return OpenConnectRekeyMethod.None;
                if (string.Equals(RekeyMethod, "ssl", StringComparison.OrdinalIgnoreCase))
                    return OpenConnectRekeyMethod.Ssl;
                if (string.Equals(RekeyMethod, "new-tunnel", StringComparison.OrdinalIgnoreCase))
                    return OpenConnectRekeyMethod.NewTunnel;
                return OpenConnectRekeyMethod.None; // "none" or an unknown method
            }
        }

        /// <summary>The session cookie echoed by the server (<c>Set-Cookie: webvpn=…</c>), if present on the CONNECT response.</summary>
        public string? SessionCookie { get; set; }

        // ---- DTLS data path (X-DTLS-*) — the parallel UDP/DTLS tunnel the client may open alongside CSTP-over-TLS ----

        /// <summary>The DTLS session id (<c>X-DTLS-Session-ID</c>), used as the cookie that ties the UDP/DTLS session to this CSTP session (legacy path); null when the gateway offers no DTLS.</summary>
        public string? DtlsSessionId { get; set; }

        /// <summary>
        /// The DTLS application id (<c>X-DTLS-App-ID</c>, hex, 16–32 bytes) the <b>PSK</b> path copies, hex-decoded, into
        /// the DTLS <c>ClientHello.session_id</c> to correlate the UDP session with the CSTP one; null on the legacy path.
        /// </summary>
        public string? DtlsAppId { get; set; }

        /// <summary>The DTLS cipher suite the gateway selected (<c>X-DTLS-CipherSuite</c>): <c>PSK-NEGOTIATE</c> for the modern PSK path, an OpenSSL name (e.g. <c>AES256-SHA</c>) for legacy; null when unset.</summary>
        public string? DtlsCipherSuite { get; set; }

        /// <summary>The DTLS MTU the gateway advertised (<c>X-DTLS-MTU</c>); falls back to the CSTP MTU when unset.</summary>
        public int? DtlsMtu { get; set; }

        /// <summary>The UDP port the DTLS data path connects to (<c>X-DTLS-Port</c>); null = DTLS not offered.</summary>
        public int? DtlsPort { get; set; }

        /// <summary>The DTLS keep-alive interval in seconds (<c>X-DTLS-Keepalive</c>); falls back to <see cref="Keepalive"/> when unset.</summary>
        public int? DtlsKeepalive { get; set; }

        /// <summary>The DTLS dead-peer-detection interval in seconds (<c>X-DTLS-DPD</c>); falls back to <see cref="Dpd"/> when unset.</summary>
        public int? DtlsDpd { get; set; }

        /// <summary>True when the gateway advertised a usable <b>legacy</b> DTLS data path (a session id and a port).</summary>
        public bool HasDtls => !string.IsNullOrEmpty(DtlsSessionId) && DtlsPort.HasValue && DtlsPort.Value > 0;

        /// <summary>
        /// True when the gateway accepted the modern <b>DTLS 1.2 PSK</b> path: it echoed <c>X-DTLS-CipherSuite:
        /// PSK-NEGOTIATE</c> and supplied an App-ID and a port. The PSK path is preferred over <see cref="HasDtls"/>.
        /// </summary>
        public bool HasDtlsPsk =>
            string.Equals(DtlsCipherSuite?.Trim(), "PSK-NEGOTIATE", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrEmpty(DtlsAppId) && DtlsPort.HasValue && DtlsPort.Value > 0;

        /// <summary>Maps the parsed headers onto a <see cref="TunnelConfig"/> for the userspace stack.</summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig
            {
                AssignedAddress = Address,
                AssignedAddressV6 = AddressV6,
                PrefixLengthV6 = PrefixLengthV6,
            };
            if (Netmask != null) config.PrefixLength = MaskToPrefix(Netmask);
            if (Mtu.HasValue) config.Mtu = Mtu.Value;
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            foreach (string route in Routes) config.Routes.Add(route);
            return config;
        }

        static int MaskToPrefix(IPAddress mask)
        {
            int bits = 0;
            foreach (byte b in mask.GetAddressBytes())
            {
                byte v = b;
                while (v != 0) { bits += v & 1; v >>= 1; }
            }
            return bits;
        }
    }
}
