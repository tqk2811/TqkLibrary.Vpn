using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Tailscale.Control;
using TqkLibrary.VpnClient.Tailscale.Control.Messages;

namespace TqkLibrary.VpnClient.Drivers.Tailscale.Tests
{
    /// <summary>
    /// A fake ts2021 control client that returns a canned netmap (or throws a canned error) without any server. Lets the
    /// driver be exercised offline: the control plane is replaced, the netmap-to-WireGuard mapping and the driver wiring
    /// run for real. Throwaway test scaffolding.
    /// </summary>
    sealed class FakeTailscaleControlClient : ITailscaleControlClient
    {
        readonly MapResponse? _map;
        readonly Exception? _error;

        public FakeTailscaleControlClient(MapResponse map) => _map = map;
        public FakeTailscaleControlClient(Exception error) => _error = error;

        public string? LastPreauthKey { get; private set; }
        public bool Disposed { get; private set; }

        public Task<MapResponse> LoginAsync(string preauthKey, CancellationToken cancellationToken = default)
        {
            LastPreauthKey = preauthKey;
            if (_error is not null) return Task.FromException<MapResponse>(_error);
            return Task.FromResult(_map!);
        }

        public void Dispose() => Disposed = true;
    }
}
