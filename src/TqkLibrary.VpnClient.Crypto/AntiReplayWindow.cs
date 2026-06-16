namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// A 64-packet sliding anti-replay window over 32-bit sequence/packet-id numbers (RFC 4303 §3.4.3 model).
    /// Bit 0 of the bitmap tracks the highest sequence seen; bit N tracks the packet N positions behind it. Shared by
    /// ESP (IPsec data plane) and the OpenVPN AEAD data channel — both number their first packet 1.
    /// </summary>
    public sealed class AntiReplayWindow
    {
        const int WindowSize = 64;
        ulong _bitmap;
        uint _highest;

        /// <summary>The highest sequence number accepted so far (0 until the first packet).</summary>
        public uint Highest => _highest;

        /// <summary>
        /// Returns true if <paramref name="sequence"/> is acceptable (new, or within the window and not yet seen).
        /// Pure check — does not record the sequence; call <see cref="Commit"/> only after integrity passes.
        /// </summary>
        public bool Check(uint sequence)
        {
            if (sequence == 0) return false; // the first packet is sequence 1 (RFC 4303; OpenVPN packet-id likewise).
            if (sequence > _highest) return true; // ahead of the window — always fresh.
            uint behind = _highest - sequence;
            if (behind >= WindowSize) return false; // older than the window — assume replay.
            return (_bitmap & (1UL << (int)behind)) == 0;
        }

        /// <summary>Records <paramref name="sequence"/> as seen, advancing the window if it is the new highest.</summary>
        public void Commit(uint sequence)
        {
            if (sequence > _highest)
            {
                uint advance = sequence - _highest;
                _bitmap = advance >= WindowSize ? 1UL : (_bitmap << (int)advance) | 1UL;
                _highest = sequence;
            }
            else
            {
                uint behind = _highest - sequence;
                if (behind < WindowSize)
                    _bitmap |= 1UL << (int)behind;
            }
        }
    }
}
