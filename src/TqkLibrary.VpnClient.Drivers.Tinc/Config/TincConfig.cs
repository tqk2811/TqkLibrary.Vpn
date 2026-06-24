using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Tinc.Hosts;

namespace TqkLibrary.VpnClient.Drivers.Tinc.Config
{
    /// <summary>
    /// A static tinc configuration — the parts of a tinc setup the client needs to bring a point-to-point tunnel up to
    /// one peer node. tinc does no in-tunnel address negotiation (each node's overlay <c>Subnet</c> is declared in its
    /// host file), so the tunnel address / routes / MTU are known up front and map straight to a
    /// <see cref="TunnelConfig"/>.
    /// <para>
    /// The cryptographic identity is this node's 32-byte Ed25519 <see cref="PrivateKey"/> seed (signs the SPTPS SIG) and
    /// the trusted <see cref="PeerHost"/> host file (its <c>Ed25519PublicKey</c> verifies the peer's SIG, its
    /// <c>Address</c>/<c>Port</c> give the real endpoint, its <c>Subnet</c>s are the routes reachable through the
    /// tunnel). <see cref="NodeName"/> is this client's tinc node name (it must be registered in the peer's
    /// <c>hosts/&lt;name&gt;</c> with our public key) and <see cref="OverlayAddress"/>/<see cref="PrefixLength"/> is the
    /// overlay IP this client owns (its own <c>Subnet</c>).
    /// </para>
    /// </summary>
    public sealed class TincConfig
    {
        /// <summary>This client's tinc node name (registered in the peer's host directory with our Ed25519 public key). Required.</summary>
        public required string NodeName { get; init; }

        /// <summary>This client's 32-byte Ed25519 private seed (signs the SPTPS SIG; its public key is registered with the peer). Required.</summary>
        public required byte[] PrivateKey { get; init; }

        /// <summary>The peer node's parsed host file (its Ed25519 public key, address, port and routed subnets). Required.</summary>
        public required TincHostConfig PeerHost { get; init; }

        /// <summary>The peer's real UDP/TCP endpoint. When null it is resolved from <see cref="TincHostConfig.Addresses"/>/<c>Port</c> (or the connect-time host:port).</summary>
        public IPEndPoint? PeerEndpoint { get; init; }

        /// <summary>This client's overlay (tunnel) IP address (its own <c>Subnet</c>). Required for a working tunnel.</summary>
        public IPAddress? OverlayAddress { get; init; }

        /// <summary>The prefix length of <see cref="OverlayAddress"/> (the host route this client owns, e.g. /32 or /24).</summary>
        public int PrefixLength { get; init; } = 32;

        /// <summary>DNS servers to use inside the tunnel; empty when none is configured.</summary>
        public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

        /// <summary>The tunnel MTU; defaults to <see cref="TincDriverConstants.DefaultMtu"/>.</summary>
        public int Mtu { get; init; } = TincDriverConstants.DefaultMtu;

        /// <summary>The peer node name (from <see cref="PeerHost"/>'s <c>Name</c>); used to build the SPTPS labels.</summary>
        public string PeerName => PeerHost.Name ?? throw new InvalidOperationException("Peer host config has no Name.");

        /// <summary>
        /// Projects this configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to the
        /// userspace IP stack. The address/prefix come from <see cref="OverlayAddress"/>; the routes are the peer's
        /// declared <c>Subnet</c>s (so traffic to the peer's overlay goes through the tunnel).
        /// </summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig
            {
                AssignedAddress = OverlayAddress,
                PrefixLength = PrefixLength,
                Mtu = Mtu,
            };
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);

            // Route the peer's declared subnets through the tunnel (point-to-point: reach the peer's overlay address).
            foreach (string subnet in PeerHost.Subnets) config.Routes.Add(subnet);
            if (config.Routes.Count == 0 && OverlayAddress is not null)
                config.Routes.Add($"{OverlayAddress}/{PrefixLength}");
            return config;
        }
    }
}
