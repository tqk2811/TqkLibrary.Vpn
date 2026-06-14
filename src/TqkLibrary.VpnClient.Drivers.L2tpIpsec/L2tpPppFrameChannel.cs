using TqkLibrary.VpnClient.L2tp;
using TqkLibrary.VpnClient.Ppp.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.L2tpIpsec
{
    /// <summary>Bridges one L2TP session's data channel to a PPP engine: PPP frames ride in L2TP data messages.</summary>
    public sealed class L2tpPppFrameChannel : IPppFrameChannel
    {
        readonly L2tpSession _session;

        /// <summary>Creates the channel over an established <see cref="L2tpSession"/>.</summary>
        public L2tpPppFrameChannel(L2tpSession session)
        {
            _session = session;
            _session.DataReceived += frame => FrameReceived?.Invoke(frame);
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? FrameReceived;

        /// <inheritdoc/>
        public ValueTask SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new ValueTask(_session.SendDataAsync(frame));
        }
    }
}
