using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Ssh.Cipher;

namespace TqkLibrary.VpnClient.Ssh.Wire
{
    /// <summary>
    /// The SSH binary packet protocol (RFC 4253 §6) over a single <see cref="IByteStreamTransport"/>. A binary packet is
    /// <c>uint32 packet_length || byte padding_length || payload || random padding</c>, padded so the encrypted portion
    /// is a multiple of the cipher block size (8 minimum) with at least 4 padding bytes. Each direction keeps a 32-bit
    /// sequence number (incremented mod 2^32 per packet, starting at 0) that feeds the cipher's nonce/MAC.
    /// <para>
    /// Before NEWKEYS the packets are sent in the clear (block size 8, no MAC) — that is how KEXINIT and the KEX messages
    /// travel. After NEWKEYS the caller installs an <see cref="ISshPacketCipher"/> for each direction via
    /// <see cref="SetOutboundCipher"/> / <see cref="SetInboundCipher"/> and every subsequent packet is sealed/opened by it.
    /// A single buffered reader straddles the cleartext→encrypted boundary so no bytes are lost. Reads are serialised by
    /// the caller (one receive loop); writes are serialised by an internal lock.
    /// </para>
    /// </summary>
    public sealed class SshPacketCodec
    {
        const int MinPadding = 4;
        const int MaxPacket = 256 * 1024; // sanity bound on an inbound packet_length

        readonly IByteStreamTransport _stream;
        readonly byte[] _readBuffer = new byte[16 * 1024];
        readonly Queue<byte> _inbound = new();
        readonly SemaphoreSlim _writeLock = new(1, 1);

        ISshPacketCipher? _outCipher;
        ISshPacketCipher? _inCipher;
        uint _outSeq;
        uint _inSeq;

        /// <summary>Wraps an already-connected byte stream. The codec starts in cleartext mode (pre-NEWKEYS).</summary>
        public SshPacketCodec(IByteStreamTransport stream)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        }

        /// <summary>Installs the outbound cipher (call on NEWKEYS sent). Until then packets are sent in the clear.</summary>
        public void SetOutboundCipher(ISshPacketCipher cipher) => _outCipher = cipher;

        /// <summary>Installs the inbound cipher (call on NEWKEYS received). Until then packets are read in the clear.</summary>
        public void SetInboundCipher(ISshPacketCipher cipher) => _inCipher = cipher;

        /// <summary>Stashes already-buffered bytes (e.g. the leftover after the version banner) so the reader sees them first.</summary>
        public void PushBackBytes(ReadOnlySpan<byte> bytes)
        {
            foreach (byte b in bytes) _inbound.Enqueue(b);
        }

        // ---- send ----

        /// <summary>
        /// Frames <paramref name="payload"/> (the SSH message: a type byte followed by the message-specific fields) into a
        /// binary packet, encrypts it with the current outbound cipher (or sends it in the clear pre-NEWKEYS) and writes it.
        /// Advances the outbound sequence number.
        /// </summary>
        public async Task WritePacketAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            byte[] packet = BuildPacket(payload.Span, _outCipher);
            byte[] wire = _outCipher is null ? packet : _outCipher.Seal(packet, _outSeq);

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await _stream.WriteAsync(wire, cancellationToken).ConfigureAwait(false);
            }
            finally { _writeLock.Release(); }
            _outSeq++;
        }

        static byte[] BuildPacket(ReadOnlySpan<byte> payload, ISshPacketCipher? cipher)
        {
            int blockSize = cipher?.BlockSize ?? 8;
            // The length field is not counted in the padded portion when the cipher encrypts the length separately
            // (chacha20-poly1305) or sends it as cleartext AAD (aes-gcm). For the cleartext mode the 4 length bytes ARE
            // part of the multiple. OpenSSH's both AEAD modes exclude the 4 length bytes from the padding calculation.
            bool lengthCounted = cipher is null;
            int unpadded = (lengthCounted ? 4 : 0) + 1 + payload.Length; // [length] + padding_length + payload
            int padding = blockSize - (unpadded % blockSize);
            if (padding < MinPadding) padding += blockSize;

            int packetLength = 1 + payload.Length + padding; // padding_length + payload + padding
            byte[] packet = new byte[4 + packetLength];
            packet[0] = (byte)(packetLength >> 24);
            packet[1] = (byte)(packetLength >> 16);
            packet[2] = (byte)(packetLength >> 8);
            packet[3] = (byte)packetLength;
            packet[4] = (byte)padding;
            payload.CopyTo(packet.AsSpan(5));
            SshRandom.Fill(packet.AsSpan(5 + payload.Length, padding));
            return packet;
        }

        // ---- receive ----

        /// <summary>
        /// Reads one binary packet and returns its payload (the SSH message bytes, padding stripped). Authentication
        /// failure (bad MAC) or a malformed length throws <see cref="SshProtocolException"/>; a clean peer close surfaces
        /// as <see cref="EndOfStreamException"/>. Advances the inbound sequence number.
        /// </summary>
        public async Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken)
        {
            ISshPacketCipher? cipher = _inCipher;
            byte[] firstFour = await ReadExactAsync(4, cancellationToken).ConfigureAwait(false);

            uint packetLength = cipher is null
                ? (uint)((firstFour[0] << 24) | (firstFour[1] << 16) | (firstFour[2] << 8) | firstFour[3])
                : cipher.ReadLength(firstFour, _inSeq);
            if (packetLength < 1 || packetLength > MaxPacket)
                throw new SshProtocolException($"SSH inbound packet_length out of range ({packetLength}).");

            int tagLen = cipher?.TagLength ?? 0;
            byte[] rest = await ReadExactAsync((int)packetLength + tagLen, cancellationToken).ConfigureAwait(false);

            byte[] plaintextPacket;
            if (cipher is null)
            {
                plaintextPacket = new byte[4 + (int)packetLength];
                Buffer.BlockCopy(firstFour, 0, plaintextPacket, 0, 4);
                Buffer.BlockCopy(rest, 0, plaintextPacket, 4, (int)packetLength);
            }
            else
            {
                byte[] wire = new byte[4 + (int)packetLength + tagLen];
                Buffer.BlockCopy(firstFour, 0, wire, 0, 4);
                Buffer.BlockCopy(rest, 0, wire, 4, (int)packetLength + tagLen);
                plaintextPacket = new byte[4 + (int)packetLength];
                if (!cipher.Open(wire, packetLength, _inSeq, plaintextPacket))
                    throw new SshProtocolException("SSH inbound packet failed authentication (bad MAC).");
            }

            _inSeq++;

            // plaintextPacket = uint32 length || padding_length || payload || padding.
            byte paddingLength = plaintextPacket[4];
            int payloadLen = (int)packetLength - 1 - paddingLength;
            if (payloadLen < 0 || payloadLen > plaintextPacket.Length - 5)
                throw new SshProtocolException("SSH inbound packet has an invalid padding length.");
            byte[] payload = new byte[payloadLen];
            Buffer.BlockCopy(plaintextPacket, 5, payload, 0, payloadLen);
            return payload;
        }

        async Task<byte[]> ReadExactAsync(int count, CancellationToken cancellationToken)
        {
            byte[] result = new byte[count];
            int filled = 0;
            while (filled < count && _inbound.Count > 0) result[filled++] = _inbound.Dequeue();

            while (filled < count)
            {
                int read;
                try { read = await _stream.ReadAsync(_readBuffer.AsMemory(), cancellationToken).ConfigureAwait(false); }
                catch (ObjectDisposedException) { throw new EndOfStreamException("SSH connection closed."); }
                catch (System.Net.Sockets.SocketException) { throw new EndOfStreamException("SSH connection reset."); }
                if (read <= 0) throw new EndOfStreamException("SSH server closed the connection.");

                int take = Math.Min(read, count - filled);
                for (int i = 0; i < take; i++) result[filled++] = _readBuffer[i];
                for (int i = take; i < read; i++) _inbound.Enqueue(_readBuffer[i]);
            }
            return result;
        }
    }
}
