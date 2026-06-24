using System.Buffers.Binary;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Enums;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
// Alias the BouncyCastle types directly (its Crypto namespace clashes with this solution's interfaces — same pattern
// as Crypto/Salsa20.cs). The codec drives Salsa20Engine itself (rather than the Salsa20 wrapper) because it needs the
// key-stream to continue across two reads: block 0 supplies the one-time Poly1305 key, the rest encrypts the payload.
using Salsa20Engine = Org.BouncyCastle.Crypto.Engines.Salsa20Engine;
using Poly1305 = Org.BouncyCastle.Crypto.Macs.Poly1305;
using KeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;
using ParametersWithIV = Org.BouncyCastle.Crypto.Parameters.ParametersWithIV;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1
{
    /// <summary>
    /// Seals and opens VL1 packets (the ZeroTier <c>Salsa2012Poly1305</c> cipher suite). A sealed packet is
    /// <c>header(28) || encrypted(verb + payload)</c> where:
    /// <list type="bullet">
    ///   <item><description>The Salsa20/12 nonce is the 8-byte packet ID (header bytes [0..8)).</description></item>
    ///   <item><description>Key-stream block 0 (first 32 bytes) is the one-time Poly1305 key; the key-stream then
    ///   continues to encrypt the verb byte and payload (offset 27 onward).</description></item>
    ///   <item><description>Poly1305 authenticates the ciphertext; its 16-byte tag is truncated to 8 bytes and stored
    ///   in the MAC field (header bytes [19..27)).</description></item>
    /// </list>
    /// <para>
    /// <b>UNVERIFIED interop:</b> the seal/open pair is self-consistent and tamper-detecting offline, but the exact
    /// key-stream split, MAC truncation half and field offsets have not yet been cross-checked against a real
    /// <c>zerotier-one</c> peer (VM lab down). Staged for live validation.
    /// </para>
    /// </summary>
    public sealed class Vl1PacketCodec
    {
        const int Poly1305KeyBytes = 32;

        /// <summary>
        /// Builds a sealed VL1 packet from <paramref name="header"/> (cipher forced to Salsa2012Poly1305), the
        /// <paramref name="key"/> (≥ 32 bytes, the Salsa20 key) and the plaintext <paramref name="payload"/> (the
        /// bytes that follow the verb). The verb itself comes from <c>header.Verb</c>.
        /// </summary>
        public byte[] Seal(Vl1Header header, ReadOnlySpan<byte> key, ReadOnlySpan<byte> payload)
        {
            if (header is null) throw new ArgumentNullException(nameof(header));
            if (key.Length < 32) throw new ArgumentException("key must be >= 32 bytes", nameof(key));

            header.Cipher = Vl1CipherSuite.Salsa2012Poly1305;
            int plainLen = 1 + payload.Length; // verb byte + payload
            // The verb byte sits at EncryptedSectionOffset (27), so the packet is the 27-byte clear header followed by
            // the plainLen-byte encrypted section — NOT Size(28)+plainLen (that double-counts the verb byte).
            byte[] packet = new byte[Vl1Header.EncryptedSectionOffset + plainLen];

            WriteHeaderClear(header, packet);

            // Plaintext encrypted section: verb byte then payload.
            Span<byte> enc = packet.AsSpan(Vl1Header.EncryptedSectionOffset, plainLen);
            enc[0] = (byte)(((header.VerbFlags & 0x07) << 5) | ((int)header.Verb & 0x1F));
            payload.CopyTo(enc.Slice(1));

            byte[] nonce = NonceFromPacketId(header.PacketId);
            var engine = NewEngine(key, nonce);

            // Block 0 -> Poly1305 one-time key.
            byte[] polyKey = NextKeystream(engine, Poly1305KeyBytes);

            // Encrypt the section in place with the continuing key-stream.
            byte[] cipherSection = new byte[plainLen];
            engine.ProcessBytes(enc.ToArray(), 0, plainLen, cipherSection, 0);
            cipherSection.CopyTo(enc);

            // Poly1305 over the ciphertext; truncate tag to 8 bytes.
            byte[] tag = ComputeMac(polyKey, cipherSection);
            tag.AsSpan(0, Vl1Header.MacSize).CopyTo(packet.AsSpan(Vl1Header.MacOffset, Vl1Header.MacSize));

            return packet;
        }

        /// <summary>
        /// Verifies and decrypts a sealed VL1 packet. On success returns true and yields the parsed header (with verb)
        /// and the decrypted payload (the bytes after the verb). Returns false without writing payload on a malformed
        /// packet, an unsupported cipher suite or a MAC mismatch.
        /// </summary>
        public bool Open(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> key, out Vl1Header header, out byte[] payload)
        {
            header = new Vl1Header();
            payload = Array.Empty<byte>();
            // Smallest valid packet = 27-byte clear header + at least the 1-byte verb.
            if (packet.Length < Vl1Header.EncryptedSectionOffset + 1) return false;
            if (key.Length < 32) return false;

            ReadHeaderClear(packet, header);
            if (header.Cipher != Vl1CipherSuite.Salsa2012Poly1305) return false;

            int cipherLen = packet.Length - Vl1Header.EncryptedSectionOffset; // verb + payload, encrypted
            ReadOnlySpan<byte> cipherSection = packet.Slice(Vl1Header.EncryptedSectionOffset, cipherLen);

            byte[] nonce = NonceFromPacketId(header.PacketId);
            var engine = NewEngine(key, nonce);

            byte[] polyKey = NextKeystream(engine, Poly1305KeyBytes);

            // Constant-time-ish MAC check before touching the plaintext.
            byte[] expected = ComputeMac(polyKey, cipherSection);
            ReadOnlySpan<byte> got = packet.Slice(Vl1Header.MacOffset, Vl1Header.MacSize);
            if (!FixedTimeEquals(expected.AsSpan(0, Vl1Header.MacSize), got)) return false;

            byte[] plain = new byte[cipherLen];
            engine.ProcessBytes(cipherSection.ToArray(), 0, cipherLen, plain, 0);

            header.VerbFlags = (byte)((plain[0] >> 5) & 0x07);
            header.Verb = (Vl1Verb)(plain[0] & 0x1F);
            payload = plain.AsSpan(1).ToArray();
            return true;
        }

        // ---- header (clear portion) -------------------------------------------------------------------------

        static void WriteHeaderClear(Vl1Header header, Span<byte> packet)
        {
            BinaryPrimitives.WriteUInt64BigEndian(packet.Slice(0, 8), header.PacketId);
            header.Destination.Write(packet.Slice(8, ZeroTierAddress.SizeInBytes));
            header.Source.Write(packet.Slice(13, ZeroTierAddress.SizeInBytes));
            packet[18] = (byte)(((header.Flags & 0x1F) << 3) | ((int)header.Cipher & 0x07));
            // MAC field [19..27) is filled by the caller after the tag is computed.
        }

        static void ReadHeaderClear(ReadOnlySpan<byte> packet, Vl1Header header)
        {
            header.PacketId = BinaryPrimitives.ReadUInt64BigEndian(packet.Slice(0, 8));
            header.Destination = ZeroTierAddress.Read(packet.Slice(8, ZeroTierAddress.SizeInBytes));
            header.Source = ZeroTierAddress.Read(packet.Slice(13, ZeroTierAddress.SizeInBytes));
            header.Flags = (byte)((packet[18] >> 3) & 0x1F);
            header.Cipher = (Vl1CipherSuite)(packet[18] & 0x07);
        }

        // ---- crypto helpers ---------------------------------------------------------------------------------

        static byte[] NonceFromPacketId(ulong packetId)
        {
            byte[] nonce = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(nonce, packetId);
            return nonce;
        }

        static Salsa20Engine NewEngine(ReadOnlySpan<byte> key, byte[] nonce)
        {
            var engine = new Salsa20Engine(12); // Salsa20/12
            engine.Init(true, new ParametersWithIV(new KeyParameter(key.Slice(0, 32).ToArray()), nonce));
            return engine;
        }

        static byte[] NextKeystream(Salsa20Engine engine, int count)
        {
            byte[] zeros = new byte[count];
            byte[] ks = new byte[count];
            engine.ProcessBytes(zeros, 0, count, ks, 0);
            return ks;
        }

        static byte[] ComputeMac(byte[] polyKey, ReadOnlySpan<byte> data)
        {
            var mac = new Poly1305();
            mac.Init(new KeyParameter(polyKey));
            byte[] buf = data.ToArray();
            mac.BlockUpdate(buf, 0, buf.Length);
            byte[] tag = new byte[16];
            mac.DoFinal(tag, 0);
            return tag;
        }

        static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
