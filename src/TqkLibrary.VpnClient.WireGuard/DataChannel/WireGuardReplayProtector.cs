using TqkLibrary.VpnClient.Crypto;

namespace TqkLibrary.VpnClient.WireGuard.DataChannel
{
    /// <summary>
    /// A 64-packet sliding anti-replay window over WireGuard's <b>64-bit</b> transport counter (whitepaper §5.4.6,
    /// same RFC 4303 §3.4.3 sliding-window model the data plane uses). WireGuard numbers counters from 0 (its first
    /// transport packet is counter 0) and never reuses one for a key, rekeying long before <c>2^60</c> messages — so a
    /// full 64-bit window is conceptually required even though no real session reaches <c>2^32</c>.
    /// <para>
    /// The Crypto <see cref="AntiReplayWindow"/> tracks 32-bit sequence numbers and starts at 1, so it cannot be used
    /// directly. This protector <b>reuses it for the low 32 bits within one high-32 epoch</b> and tracks the high 32
    /// bits itself: the window's sequence is <c>(low32 + 1)</c> (shifting WireGuard's 0-based counter onto the
    /// AntiReplayWindow's 1-based numbering) and a fresh <see cref="AntiReplayWindow"/> is started whenever the high
    /// half advances (a forward jump of ≥2^32 is far beyond the 64-slot window, so the old epoch's bitmap is
    /// irrelevant). An older epoch (high half below the highest seen) is always rejected as a replay.
    /// </para>
    /// </summary>
    public sealed class WireGuardReplayProtector
    {
        AntiReplayWindow _window = new();
        uint _highestHigh;        // high 32 bits of the highest counter accepted
        bool _any;                // false until the first counter is committed

        /// <summary>The highest 64-bit counter accepted so far (0 until the first packet — note 0 is a valid counter).</summary>
        public ulong Highest => _any ? ((ulong)_highestHigh << 32) | (ulong)(_window.Highest - 1u) : 0UL;

        /// <summary>
        /// Returns true if <paramref name="counter"/> is acceptable (new, or within the window and not yet seen). Pure
        /// check — does not record it; call <see cref="Commit"/> only after the AEAD tag verifies.
        /// </summary>
        public bool Check(ulong counter)
        {
            uint high = (uint)(counter >> 32);
            uint low = (uint)counter;
            if (!_any) return true;                       // first packet — any counter (including 0) is fresh
            if (high > _highestHigh) return true;         // a higher epoch is always ahead of the window
            if (high < _highestHigh) return false;        // an older epoch is far behind the 64-slot window → replay
            return _window.Check(low + 1u);               // same epoch: defer to the 32-bit window (1-based)
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
                _window.Commit(low + 1u);
                return;
            }
            if (high > _highestHigh)
            {
                // The low half has wrapped past 2^32; the previous epoch's bitmap can no longer match, so reset it.
                _highestHigh = high;
                _window = new AntiReplayWindow();
                _window.Commit(low + 1u);
                return;
            }
            if (high == _highestHigh)
                _window.Commit(low + 1u);
            // high < _highestHigh ⇒ an old epoch; Commit is only ever called after Check passed, so this cannot happen.
        }
    }
}
