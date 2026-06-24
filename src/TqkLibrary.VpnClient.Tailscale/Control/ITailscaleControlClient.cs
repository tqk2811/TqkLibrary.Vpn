using TqkLibrary.VpnClient.Tailscale.Control.Messages;

namespace TqkLibrary.VpnClient.Tailscale.Control
{
    /// <summary>
    /// The ts2021 control-plane surface the Tailscale driver depends on: log in with a preauth key and return the
    /// netmap. Behind an interface so the driver can be driven offline with a fake that serves a canned
    /// <see cref="MapResponse"/> (no real server), while the production <see cref="TailscaleControlClient"/> talks to a
    /// real Headscale/Tailscale server over the Noise channel.
    /// </summary>
    public interface ITailscaleControlClient : IDisposable
    {
        /// <summary>
        /// Logs the node in with <paramref name="preauthKey"/> and returns the first full netmap. Throws
        /// <see cref="TailscaleControlException"/> on a rejected key, an unauthorised node or a transport error.
        /// </summary>
        Task<MapResponse> LoginAsync(string preauthKey, CancellationToken cancellationToken = default);
    }
}
