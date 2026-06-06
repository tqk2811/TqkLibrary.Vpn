using TqkLibrary.Vpn.Ppp.Enums;
using TqkLibrary.Vpn.Ppp.Models;

namespace TqkLibrary.Vpn.Ppp
{
    /// <summary>
    /// LCP negotiator. Requests MRU (1500) and a Magic-Number; accepts the peer's MRU/Magic-Number and rejects
    /// any option it does not implement (e.g. an Authentication-Protocol it cannot satisfy).
    /// </summary>
    public sealed class LcpNegotiator : PppNegotiator
    {
        readonly uint _magic;
        ushort _mru = 1500;

        /// <summary>Creates an LCP negotiator with the given local magic number.</summary>
        public LcpNegotiator(Action<byte[]> send, uint magic) : base(send)
        {
            _magic = magic;
        }

        /// <summary>Negotiated MRU (peer's accepted value).</summary>
        public ushort Mru => _mru;

        /// <inheritdoc/>
        protected override IReadOnlyList<PppOption> BuildLocalOptions() => new[]
        {
            new PppOption((byte)LcpOptionType.Mru, new[] { (byte)(_mru >> 8), (byte)(_mru & 0xff) }),
            new PppOption((byte)LcpOptionType.MagicNumber, new[]
            {
                (byte)(_magic >> 24), (byte)(_magic >> 16), (byte)(_magic >> 8), (byte)_magic,
            }),
        };

        /// <inheritdoc/>
        protected override (byte code, IReadOnlyList<PppOption> options) EvaluatePeerRequest(List<PppOption> peerOptions)
        {
            var unsupported = peerOptions
                .Where(o => o.Type != (byte)LcpOptionType.Mru && o.Type != (byte)LcpOptionType.MagicNumber)
                .ToList();

            if (unsupported.Count > 0)
                return ((byte)PppCode.ConfigureReject, unsupported);

            return ((byte)PppCode.ConfigureAck, peerOptions);
        }
    }
}
