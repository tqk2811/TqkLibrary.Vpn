using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.Tailscale.Config;
using TqkLibrary.VpnClient.Tailscale.Control;
using TqkLibrary.VpnClient.Tailscale.Control.Messages;

namespace TqkLibrary.VpnClient.Drivers.Tailscale
{
    /// <summary>
    /// Builds the real ts2021 <see cref="TailscaleControlClient"/> from a <see cref="TailscaleConfig"/> and adapts it to
    /// <see cref="ITailscaleControlClient"/> for the driver. The HTTP/2-over-Noise control client requires .NET 5+
    /// (h2c is unavailable on the netstandard2.0 HttpClient), so on netstandard2.0 the constructor throws — a caller on
    /// that target must inject a control-client factory.
    /// </summary>
    public sealed class TailscaleControlClientAdapter : ITailscaleControlClient
    {
#if NET5_0_OR_GREATER
        readonly TailscaleControlClient _inner;

        /// <summary>Builds the real control client from the config (server URL + machine/node keys + hostname).</summary>
        public TailscaleControlClientAdapter(TailscaleConfig config)
        {
            _inner = new TailscaleControlClient(config.ServerUrl, config.MachinePrivateKey, config.NodePrivateKey,
                discoPublicKey: null, hostname: config.Hostname);
        }

        /// <inheritdoc/>
        public Task<MapResponse> LoginAsync(string preauthKey, CancellationToken cancellationToken = default)
            => _inner.LoginAsync(preauthKey, cancellationToken);

        /// <inheritdoc/>
        public void Dispose() => _inner.Dispose();
#else
        /// <summary>Not supported on netstandard2.0 (the ts2021 control plane needs HTTP/2 over the Noise channel).</summary>
        public TailscaleControlClientAdapter(TailscaleConfig config)
            => throw new System.PlatformNotSupportedException("The Tailscale ts2021 control plane requires .NET 5 or later (HTTP/2 over the Noise channel).");

        /// <inheritdoc/>
        public Task<MapResponse> LoginAsync(string preauthKey, CancellationToken cancellationToken = default)
            => throw new System.PlatformNotSupportedException();

        /// <inheritdoc/>
        public void Dispose() { }
#endif
    }
}
