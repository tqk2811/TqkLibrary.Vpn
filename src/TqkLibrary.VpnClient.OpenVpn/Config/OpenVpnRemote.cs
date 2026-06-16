using TqkLibrary.VpnClient.OpenVpn.Enums;

namespace TqkLibrary.VpnClient.OpenVpn.Config
{
    /// <summary>A server endpoint from a <c>remote host [port] [proto]</c> directive (a profile may list several).</summary>
    public sealed class OpenVpnRemote
    {
        /// <summary>Creates a remote endpoint; <paramref name="protocol"/> overrides the profile-wide proto when present.</summary>
        public OpenVpnRemote(string host, int port, OpenVpnProtocol? protocol = null)
        {
            Host = host;
            Port = port;
            Protocol = protocol;
        }

        /// <summary>The server host name or IP literal.</summary>
        public string Host { get; }

        /// <summary>The server port (the directive's own port, or the profile default).</summary>
        public int Port { get; }

        /// <summary>A per-remote transport override (third token of the directive); null ⇒ use the profile's protocol.</summary>
        public OpenVpnProtocol? Protocol { get; }
    }
}
