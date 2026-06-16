using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.WireGuard.Handshake
{
    /// <summary>
    /// Encodes an instant as the 12-byte TAI64N timestamp WireGuard stamps into the handshake-initiation message
    /// (whitepaper §5.4.2). TAI64N is 8 bytes of TAI seconds (big-endian) followed by 4 bytes of nanoseconds
    /// (big-endian); the seconds field is the Unix time plus the TAI label base <c>0x4000000000000000</c> and the
    /// 10-second leap offset baked into WireGuard's reference implementation (<c>0x400000000000000A</c>).
    /// <para>
    /// The responder only checks that successive timestamps from a given initiator are <b>strictly increasing</b>
    /// (a greatest-timestamp anti-replay), so the exact epoch handling matters far less than monotonicity:
    /// <see cref="Now"/> reads the wall clock, while <see cref="Encode(DateTimeOffset)"/> lets callers (and tests)
    /// stamp a chosen instant deterministically. The 12-byte big-endian encoding is itself monotone, so a plain
    /// lexicographic byte comparison (<see cref="Compare"/>) orders two timestamps.
    /// </para>
    /// </summary>
    public sealed class WireGuardTai64n
    {
        /// <summary>TAI64 label base (2^62) plus WireGuard's reference 10-second offset, added to the Unix second count.</summary>
        const ulong Tai64Base = 0x400000000000000AUL;

        const long NanosPerSecond = 1_000_000_000L;
        const long TicksPerNano = 100L; // one .NET tick = 100 ns; 1 ns = 1/100 tick

        /// <summary>Length of a TAI64N timestamp in bytes (8-byte seconds + 4-byte nanoseconds).</summary>
        public const int Length = WireGuardConstants.TimestampLength;

        /// <summary>Encodes the current wall-clock instant (UTC) as TAI64N.</summary>
        public byte[] Now() => Encode(DateTimeOffset.UtcNow);

        /// <summary>Encodes the current wall-clock instant (UTC) as TAI64N into <paramref name="destination"/> (12 bytes).</summary>
        public void Now(Span<byte> destination) => Encode(DateTimeOffset.UtcNow, destination);

        /// <summary>Encodes <paramref name="instant"/> as a fresh 12-byte TAI64N array.</summary>
        public byte[] Encode(DateTimeOffset instant)
        {
            byte[] output = new byte[Length];
            Encode(instant, output);
            return output;
        }

        /// <summary>
        /// Encodes <paramref name="instant"/> as TAI64N into <paramref name="destination"/> (must be ≥ 12 bytes):
        /// big-endian TAI seconds in bytes 0..7, big-endian nanoseconds in bytes 8..11.
        /// </summary>
        public void Encode(DateTimeOffset instant, Span<byte> destination)
        {
            if (destination.Length < Length)
                throw new ArgumentException($"TAI64N needs at least {Length} bytes.", nameof(destination));

            long unixSeconds = instant.ToUnixTimeSeconds();
            // Sub-second remainder of the instant, expressed in nanoseconds (0 .. 999_999_999).
            long subSecondTicks = instant.UtcTicks - DateTimeOffset.FromUnixTimeSeconds(unixSeconds).UtcTicks;
            uint nanoseconds = (uint)(subSecondTicks * TicksPerNano % NanosPerSecond);

            ulong taiSeconds = Tai64Base + (ulong)unixSeconds;
            BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(0, 8), taiSeconds);
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8, 4), nanoseconds);
        }

        /// <summary>
        /// Orders two TAI64N timestamps the way the responder's greatest-timestamp check does: a lexicographic
        /// comparison of the 12 big-endian bytes. Returns &lt; 0 / 0 / &gt; 0 when <paramref name="left"/> is
        /// earlier than / equal to / later than <paramref name="right"/>.
        /// </summary>
        public int Compare(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            int n = Math.Min(left.Length, right.Length);
            for (int i = 0; i < n; i++)
            {
                int d = left[i] - right[i];
                if (d != 0) return d;
            }
            return left.Length - right.Length;
        }
    }
}
