using TqkLibrary.VpnClient.Crypto;

namespace TqkLibrary.VpnClient.Drivers.Nebula.DataChannel
{
    /// <summary>
    /// A 64-packet sliding anti-replay window over Nebula's <b>64-bit</b> message counter (header bytes 8-15). Nebula
    /// numbers its first data packet 1 and never reuses a counter for a key, so a full 64-bit window is conceptually
    /// required even though no real session reaches <c>2^32</c>.
    /// <para>
    /// The Crypto <see cref="AntiReplayWindow"/> tracks 32-bit sequences and starts at 1, so it cannot be used
    /// directly. This protector <b>reuses it for the low 32 bits within one high-32 epoch</b> and tracks the high 32
    /// bits itself, mirroring <c>WireGuardReplayProtector</c> (which itself reuses <see cref="AntiReplayWindow"/>). The
    /// window's sequence is <c>low32</c> directly (Nebula's first counter is 1, matching <see cref="AntiReplayWindow"/>'s
    /// 1-based numbering); a fresh window is started whenever the high half advances, and an older epoch is rejected.
    /// </para>
    /// </summary>
    public sealed class NebulaReplayProtector
    {
        AntiReplayWindow _window = new();
        uint _highestHigh;        // high 32 bits of the highest counter accepted
        bool _any;                // false until the first counter is committed

        /// <summary>The highest 64-bit counter accepted so far (0 until the first packet).</summary>
        public ulong Highest => _any ? ((ulong)_highestHigh << 32) | _window.Highest : 0UL;

        /// <summary>
        /// Returns true if <paramref name="counter"/> is acceptable (new, or within the window and not yet seen). Pure
        /// check — does not record it; call <see cref="Commit"/> only after the AEAD tag verifies.
        /// </summary>
        public bool Check(ulong counter)
        {
            uint high = (uint)(counter >> 32);
            uint low = (uint)counter;
            if (low == 0 && high == 0) return false;   // counter 0 is never a valid data packet (first is 1)
            if (!_any) return true;                    // first packet — any non-zero counter is fresh
            if (high > _highestHigh) return true;      // a higher epoch is always ahead of the window
            if (high < _highestHigh) return false;     // an older epoch is far behind the 64-slot window → replay
            return _window.Check(low);                 // same epoch: defer to the 32-bit window
        }

        /// <summary>Records <paramref name="counter"/> as seen, advancing the window (and epoch) if it is the new highest.</summary>
        public void Commit(ulong counter)
        {
            uint high = (uint)(counter >> 32);
            uint low = (uint)counter;
            if (!_any)
            {
                _any = true;
                _highestHigh = high;
                _window.Commit(low);
                return;
            }
            if (high > _highestHigh)
            {
                _highestHigh = high;
                _window = new AntiReplayWindow();
                _window.Commit(low);
                return;
            }
            if (high == _highestHigh)
                _window.Commit(low);
            // high < _highestHigh ⇒ an old epoch; Commit is only ever called after Check passed, so this cannot happen.
        }
    }
}
