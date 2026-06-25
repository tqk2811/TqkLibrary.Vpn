using System.Buffers.Binary;
using System.Text;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.N2n.Wire;

namespace TqkLibrary.VpnClient.N2n
{
    /// <summary>
    /// n2n v3 <b>header encryption</b> (<c>-H</c>) — the optional layer that hides the cleartext common header
    /// (community + flags) from passive DPI and adds a checksum + timestamp anti-replay. It is keyed solely by the
    /// community name (no separate password): the SPECK key is <c>pearson_hash_128(community)</c> and the IV-block key is
    /// <c>pearson_hash_128</c> of that, matching <c>packet_header_setup_key</c>. This implements the
    /// <c>packet_header_encrypt</c> / <c>packet_header_decrypt</c> framing byte-exact (verified live against n2n v3.1.1
    /// with golden vectors) using <see cref="Speck"/> + <see cref="PearsonHash"/> from Crypto.
    /// <para>
    /// On the wire the first 16 bytes become an encrypted IV block carrying a 64-bit Pearson checksum of the whole
    /// packet XOR-ed with a 64-bit timestamp plus random bits; bytes <c>16..header_len</c> (the rest of the common
    /// header) are SPECK-CTR encrypted with that IV, the four bytes at offset 16 carrying the magic
    /// <c>0x6E320000 + header_len</c> ("n2__") that the receiver checks to recognise a valid header for this community.
    /// The payload (the PACKET body past <c>header_len</c>) is <b>not</b> touched — it is protected separately by the
    /// transform (NULL / AES / …).
    /// </para>
    /// </summary>
    public sealed class N2nHeaderEncryption
    {
        /// <summary>Magic base (<c>0x6E320000</c>, ASCII "n2\0\0"); <c>header_len</c> is added to it.</summary>
        public const uint MagicBase = 0x6E320000;

        const int IvBlockSize = 16;          // the first 16 bytes form the encrypted IV/checksum block
        const int CommunitySize = N2nConstants.CommunitySize; // 20

        readonly Speck _ctx;        // keyed with pearson128(community)
        readonly Speck _ctxIv;      // keyed with pearson128(pearson128(community))
        readonly byte[] _communityPadded = new byte[CommunitySize];

        /// <summary>Builds the header-encryption keys from the community name (≤ 20 ASCII bytes, null-padded).</summary>
        public N2nHeaderEncryption(string community)
        {
            if (community is null) throw new ArgumentNullException(nameof(community));
            byte[] commBytes = Encoding.ASCII.GetBytes(community);
            int n = Math.Min(commBytes.Length, CommunitySize);
            commBytes.AsSpan(0, n).CopyTo(_communityPadded);

            byte[] key = PearsonHash.Hash128(_communityPadded);   // SPECK key = pearson128(community, 20)
            byte[] ivKey = PearsonHash.Hash128(key);              // IV key = pearson128(key, 16)
            _ctx = new Speck(key);
            _ctxIv = new Speck(ivKey);
        }

        /// <summary>
        /// Encrypts the header of <paramref name="packet"/> in place (the full datagram, length <paramref name="packetLen"/>).
        /// <paramref name="headerLen"/> is the number of leading bytes that form the header (the 24-byte common header).
        /// <paramref name="stamp"/> is the sender's monotonic timestamp (microseconds) for anti-replay. The payload past
        /// <paramref name="headerLen"/> is left untouched. Returns false if the packet is too short (&lt; 24).
        /// </summary>
        public bool Encrypt(Span<byte> packet, int headerLen, int packetLen, ulong stamp, ReadOnlySpan<byte> random16)
        {
            if (packetLen < 24 || packet.Length < packetLen) return false;
            uint magic = MagicBase + (uint)headerLen;

            // checksum over the whole packet in its current (cleartext-header) form.
            ulong checksum = PearsonHash.Hash64(packet.Slice(0, packetLen));

            // Re-order: save version/ttl/flags (bytes 0..3) into bytes 20..23.
            packet.Slice(0, 4).CopyTo(packet.Slice(20, 4));

            // pre-IV = checksum(0..7) ‖ (community[0..3] XOR high-stamp)(4..7) ‖ low-stamp(8..11) ‖ random(12..15).
            BinaryPrimitives.WriteUInt64BigEndian(packet.Slice(0, 8), checksum);
            uint high = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(4, 4)) ^ (uint)(stamp >> 32);
            BinaryPrimitives.WriteUInt32BigEndian(packet.Slice(4, 4), high);
            BinaryPrimitives.WriteUInt32BigEndian(packet.Slice(8, 4), (uint)stamp);
            (random16.Length >= 4 ? random16.Slice(0, 4) : stackalloc byte[4]).CopyTo(packet.Slice(12, 4));

            // Encrypt the 16-byte pre-IV block to the IV.
            EncryptIvBlock(packet);

            // magic at offset 16, then SPECK-CTR over bytes [16 .. headerLen) with IV = the encrypted block.
            BinaryPrimitives.WriteUInt32BigEndian(packet.Slice(16, 4), magic);
            CtrHeader(packet, headerLen);
            return true;
        }

        /// <summary>
        /// Decrypts the header of <paramref name="packet"/> in place. On success returns true, restores the original
        /// cleartext common header, and outputs the sender <paramref name="stamp"/>. Returns false if the magic / checksum
        /// does not match this community (wrong community, not header-encrypted, or tampered).
        /// </summary>
        public bool Decrypt(Span<byte> packet, int packetLen, out ulong stamp)
        {
            stamp = 0;
            if (packetLen < 24 || packet.Length < packetLen) return false;

            // Decrypt the 4 magic bytes at offset 16 with CTR (IV = current first 16 bytes, still the encrypted block).
            Span<byte> magicBytes = stackalloc byte[4];
            Span<byte> iv = stackalloc byte[IvBlockSize];
            packet.Slice(0, IvBlockSize).CopyTo(iv);
            CtrXor(iv, packet.Slice(16, 4), magicBytes);
            uint testMagic = BinaryPrimitives.ReadUInt32BigEndian(magicBytes);
            long headerLen = (long)testMagic - MagicBase;
            if (headerLen < 24 || headerLen > packetLen) return false;

            // Decrypt the remaining header bytes [16 .. headerLen) with CTR (same IV = encrypted block).
            int rest = (int)headerLen - 16;
            Span<byte> headerCt = packet.Slice(16, rest).ToArray();
            CtrXor(iv, headerCt, packet.Slice(16, rest));

            // Decrypt the IV block to recover the pre-IV (checksum / stamp).
            DecryptIvBlock(packet);

            ulong rawStamp = BinaryPrimitives.ReadUInt64BigEndian(packet.Slice(4, 8));
            uint checksumHigh = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(0, 4));

            // Restore the original packet order: version/ttl/flags from bytes 20..23, community at offset 4.
            packet.Slice(20, 4).CopyTo(packet.Slice(0, 4));
            _communityPadded.AsSpan().CopyTo(packet.Slice(4, CommunitySize));

            ulong checksum = PearsonHash.Hash64(packet.Slice(0, packetLen));
            if ((uint)(checksum >> 32) != checksumHigh) return false;

            stamp = rawStamp ^ (checksum << 32);
            return true;
        }

        // ---- internals ----------------------------------------------------------------------------------------

        void EncryptIvBlock(Span<byte> packet)
        {
            Span<byte> block = stackalloc byte[IvBlockSize];
            packet.Slice(0, IvBlockSize).CopyTo(block);
            _ctxIv.EncryptBlock(block);
            block.CopyTo(packet.Slice(0, IvBlockSize));
        }

        void DecryptIvBlock(Span<byte> packet)
        {
            Span<byte> block = stackalloc byte[IvBlockSize];
            packet.Slice(0, IvBlockSize).CopyTo(block);
            _ctxIv.DecryptBlock(block);
            block.CopyTo(packet.Slice(0, IvBlockSize));
        }

        // CTR over the header bytes [16 .. headerLen), IV = the (already encrypted) first 16 bytes of the packet.
        void CtrHeader(Span<byte> packet, int headerLen)
        {
            Span<byte> iv = stackalloc byte[IvBlockSize];
            packet.Slice(0, IvBlockSize).CopyTo(iv);
            int rest = headerLen - 16;
            Span<byte> src = packet.Slice(16, rest).ToArray();
            CtrXor(iv, src, packet.Slice(16, rest));
        }

        void CtrXor(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output) => _ctx.Ctr(iv, input, output);
    }
}
