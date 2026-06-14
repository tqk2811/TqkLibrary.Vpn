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
        uint _sequence; // last sequence used outbound; first packet is 1 (RFC 4303 §3.3.3).

        /// <summary>Creates the pair from the two unidirectional SAs negotiated for this CHILD_SA.</summary>
        public EspSession(uint outboundSpi, EspCipherSuite outbound, uint inboundSpi, EspCipherSuite inbound)
        {
            _outboundSpi = outboundSpi;
            _outbound = outbound;
            _inboundSpi = inboundSpi;
            _inbound = inbound;
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
            if (packet.Length < EspConstants.HeaderSize) return false;
            if (EspConstants.ReadSpi(packet) != _inboundSpi) return false;

            uint sequence = EspConstants.ReadSequence(packet);
            if (!_replay.Check(sequence)) return false;
            if (!_inbound.TryUnprotect(packet, out payload, out nextHeader)) return false;

            _replay.Commit(sequence);
            return true;
        }
    }
}
