using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Crypto;

namespace TqkLibrary.VpnClient.Ipsec.Esp
{
    /// <summary>
    /// A bidirectional ESP security association pair: an outbound transform with a monotonic sequence counter and an
    /// inbound transform guarded by an <see cref="AntiReplayWindow"/>. This is the unit the data plane sends through.
    /// </summary>
    public sealed class EspSession
    {
        readonly uint _outboundSpi;
        readonly uint _inboundSpi;
        readonly EspCipherSuite _outbound;
        readonly EspCipherSuite _inbound;
        readonly AntiReplayWindow _replay = new();
        readonly ILogger _logger;
        uint _sequence; // last sequence used outbound; first packet is 1 (RFC 4303 §3.3.3).

        const string Layer = "esp";

        /// <summary>
        /// Creates the pair from the two unidirectional SAs negotiated for this CHILD_SA. <paramref name="logger"/>
        /// receives the SA-install trace and classified inbound-drop reasons (replay / decrypt-failed); null logs to a
        /// no-op logger (no behaviour change).
        /// </summary>
        public EspSession(uint outboundSpi, EspCipherSuite outbound, uint inboundSpi, EspCipherSuite inbound,
            ILogger? logger = null)
        {
            _outboundSpi = outboundSpi;
            _outbound = outbound;
            _inboundSpi = inboundSpi;
            _inbound = inbound;
            _logger = logger ?? NullLogger.Instance;
            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogProtocolStep(Layer, $"SA installed: outbound SPI=0x{outboundSpi:x8}, inbound SPI=0x{inboundSpi:x8}");
        }

        /// <summary>The SPI the peer uses to recognise packets we send.</summary>
        public uint OutboundSpi => _outboundSpi;

        /// <summary>The SPI we expect on packets the peer sends us.</summary>
        public uint InboundSpi => _inboundSpi;

        /// <summary>
        /// The last sequence number assigned outbound (0 before the first packet). Exposed so the data plane can
        /// rekey before it reaches 2^32 — past that <see cref="Protect"/> would overflow rather than wrap, which
        /// RFC 4303 §3.3.3 forbids without a fresh SA.
        /// </summary>
        public uint OutboundSequence => _sequence;

        /// <summary>Encrypts <paramref name="payload"/> into a new ESP packet, assigning the next sequence number.</summary>
        public byte[] Protect(ReadOnlySpan<byte> payload, byte nextHeader = EspConstants.NextHeaderUdp)
        {
            uint sequence = checked(_sequence + 1);
            _sequence = sequence;
            return _outbound.Protect(_outboundSpi, sequence, payload, nextHeader);
        }

        /// <summary>
        /// Validates SPI, anti-replay, and integrity, then decrypts. Returns false (writing nothing) on any failure;
        /// the replay window only advances once the packet authenticates.
        /// </summary>
        public bool TryUnprotect(ReadOnlySpan<byte> packet, out byte[] payload, out byte nextHeader)
        {
            payload = Array.Empty<byte>();
            nextHeader = 0;
            if (packet.Length < EspConstants.HeaderSize)
            {
                if (_logger.IsEnabled(LogLevel.Debug)) _logger.LogPacketDropped(Layer, VpnDropReason.Malformed, "shorter than ESP header");
                return false;
            }
            // An SPI that is not ours is not a drop here — it is demux: the data plane offers the same packet to the
            // pre-rekey SA (EspDataPlane.TryUnprotectInbound). Stay silent so a healthy make-before-break window is quiet.
            if (EspConstants.ReadSpi(packet) != _inboundSpi) return false;

            uint sequence = EspConstants.ReadSequence(packet);
            if (!_replay.Check(sequence))
            {
                if (_logger.IsEnabled(LogLevel.Debug)) _logger.LogPacketDropped(Layer, VpnDropReason.Replay, $"seq={sequence} outside/at window");
                return false;
            }
            if (!_inbound.TryUnprotect(packet, out payload, out nextHeader))
            {
                if (_logger.IsEnabled(LogLevel.Debug)) _logger.LogPacketDropped(Layer, VpnDropReason.DecryptFailed, $"seq={sequence} ICV/decrypt failed");
                return false;
            }

            _replay.Commit(sequence);
            return true;
        }
    }
}
