using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ssh;
using TqkLibrary.VpnClient.Ssh.Transport;

namespace TqkLibrary.VpnClient.Drivers.Ssh.Config
{
    /// <summary>
    /// A static SSH (VPN-over-SSH) client configuration — what the client needs to bring a point-to-point tun@openssh.com
    /// tunnel up to one OpenSSH server. SSH does no in-tunnel address negotiation (the server's
    /// <c>Tunnel</c>/<c>PermitTunnel</c> + the admin's network scripts configure the server tun device), so the client's
    /// tunnel address / peer / routes are supplied out-of-band here and map straight to a <see cref="TunnelConfig"/>.
    /// <para>
    /// Authentication is either a 32-byte Ed25519 private-key seed (<see cref="PrivateKeyEd25519"/>, the publickey method)
    /// or a <see cref="Password"/>. <see cref="RemoteTunUnit"/> selects the server tun interface (the server's
    /// <c>PermitTunnel</c> unit), or <see cref="SshClientOptions.AnyTunUnit"/> to let the server choose.
    /// <see cref="HostKeyValidator"/> can pin the server host key (TOFU); null accepts any host key whose signature over
    /// the exchange hash verified.
    /// </para>
    /// </summary>
    public sealed class SshConfig
    {
        /// <summary>The SSH login user name. Required.</summary>
        public required string Username { get; init; }

        /// <summary>The 32-byte Ed25519 private-key seed for publickey auth; null to use <see cref="Password"/> instead.</summary>
        public byte[]? PrivateKeyEd25519 { get; init; }

        /// <summary>The password for password auth; used only when <see cref="PrivateKeyEd25519"/> is null.</summary>
        public string? Password { get; init; }

        /// <summary>The remote tun unit number to request (default: let the server choose).</summary>
        public uint RemoteTunUnit { get; init; } = SshClientOptions.AnyTunUnit;

        /// <summary>This client's tunnel IP address (the server tun device's point-to-point peer). Required for a working tunnel.</summary>
        public IPAddress? TunnelAddress { get; init; }

        /// <summary>The prefix length of <see cref="TunnelAddress"/> (default /32 for a point-to-point link).</summary>
        public int PrefixLength { get; init; } = 32;

        /// <summary>The server's tunnel IP address (the inner gateway / ping target); used to add a host route.</summary>
        public IPAddress? PeerAddress { get; init; }

        /// <summary>DNS servers to use inside the tunnel; empty when none is configured.</summary>
        public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

        /// <summary>The tunnel MTU; defaults to <see cref="SshDriverConstants.DefaultMtu"/>.</summary>
        public int Mtu { get; init; } = SshDriverConstants.DefaultMtu;

        /// <summary>An optional host-key validator (TOFU pinning): true to accept, false to refuse. Null accepts any verified host key.</summary>
        public Func<SshEd25519HostKey, bool>? HostKeyValidator { get; init; }

        /// <summary>Builds the <see cref="SshClientOptions"/> the SSH client consumes from this config.</summary>
        public SshClientOptions ToClientOptions() => new SshClientOptions
        {
            Username = Username,
            PrivateKeyEd25519 = PrivateKeyEd25519,
            Password = Password,
            RemoteTunUnit = RemoteTunUnit,
            HostKeyValidator = HostKeyValidator,
        };

        /// <summary>
        /// Projects this configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to the
        /// userspace IP stack. The address/prefix come from <see cref="TunnelAddress"/>; a host route to
        /// <see cref="PeerAddress"/> is added so traffic to the server's tunnel IP goes through the tunnel.
        /// </summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig
            {
                AssignedAddress = TunnelAddress,
                PrefixLength = PrefixLength,
                Mtu = Mtu,
            };
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            if (PeerAddress is not null) config.Routes.Add($"{PeerAddress}/32");
            return config;
        }
    }
}
