using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Crypto;

namespace TqkLibrary.VpnClient.SoftEther.DataChannel
{
    /// <summary>
    /// An <see cref="IByteStreamTransport"/> decorator that adds the SoftEther <c>use_encrypt</c> RC4 layer over an
    /// inner (already TLS-established) byte stream. SoftEther's payload encryption sits <b>below</b> the data-block
    /// framing: a continuous RC4 keystream runs over the post-TLS byte stream, one independent keystream per direction.
    /// This decorator therefore RC4-encrypts every byte written and RC4-decrypts every byte read, transparently — the
    /// block reader/codec above it (<see cref="SoftEtherDataBlockReader"/> / <see cref="SoftEtherDataFrameCodec"/>) keep
    /// working on plaintext block bytes and never see the cipher.
    /// <para>
    /// Because RC4 is order-sensitive (each keystream byte is consumed exactly once, in order), the two directions must
    /// use <b>distinct</b> keystreams: this end's send key must equal the peer's receive key and vice-versa. The keys are
    /// derived from a shared secret (the session key the server returns in the <c>welcome</c> PACK) by tagging it with a
    /// fixed per-direction label, so the client and server end up mirror-symmetric. RC4 is cryptographically broken
    /// (RFC 7465) — provided only for SoftEther legacy <c>use_encrypt</c> compatibility on top of TLS, never as the sole
    /// protection. Re-implemented from the protocol behavior (spec doc <c>07</c>) — not copied from the GPL source.
    /// </para>
    /// </summary>
    public sealed class SoftEtherEncryptedTransport : IByteStreamTransport
    {
        readonly IByteStreamTransport _inner;
        readonly Rc4 _sendCipher;
        readonly Rc4 _receiveCipher;

        SoftEtherEncryptedTransport(IByteStreamTransport inner, ReadOnlySpan<byte> sendKey, ReadOnlySpan<byte> receiveKey)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _sendCipher = new Rc4(sendKey);
            _receiveCipher = new Rc4(receiveKey);
        }

        /// <summary>
        /// Wraps <paramref name="inner"/> for the <b>client</b> role: the client send keystream encrypts client→server,
        /// the receive keystream decrypts server→client. <paramref name="sessionKey"/> is the shared session-key handle
        /// from the <c>welcome</c> PACK; the two direction keys are derived from it via <see cref="DeriveDirectionKeys"/>.
        /// </summary>
        public static SoftEtherEncryptedTransport CreateClient(IByteStreamTransport inner, ReadOnlySpan<byte> sessionKey)
        {
            (byte[] clientToServer, byte[] serverToClient) = DeriveDirectionKeys(sessionKey);
            return new SoftEtherEncryptedTransport(inner, clientToServer, serverToClient);
        }

        /// <summary>
        /// Wraps <paramref name="inner"/> for the <b>server/responder</b> role (used by the offline interop tests): the
        /// directions are swapped relative to <see cref="CreateClient"/> so the two ends mirror each other.
        /// </summary>
        public static SoftEtherEncryptedTransport CreateServer(IByteStreamTransport inner, ReadOnlySpan<byte> sessionKey)
        {
            (byte[] clientToServer, byte[] serverToClient) = DeriveDirectionKeys(sessionKey);
            return new SoftEtherEncryptedTransport(inner, serverToClient, clientToServer);
        }

        /// <summary>
        /// Derives the two independent RC4 direction keys from the shared <paramref name="sessionKey"/>: each is the raw
        /// session key followed by a fixed one-byte direction label (0x01 = client→server, 0x02 = server→client). A
        /// distinct keystream per direction is required because RC4 keystream bytes are consumed in order.
        /// </summary>
        public static (byte[] clientToServer, byte[] serverToClient) DeriveDirectionKeys(ReadOnlySpan<byte> sessionKey)
        {
            if (sessionKey.Length == 0)
                throw new ArgumentException("SoftEther use_encrypt needs a non-empty session key.", nameof(sessionKey));
            return (WithLabel(sessionKey, 0x01), WithLabel(sessionKey, 0x02));
        }

        static byte[] WithLabel(ReadOnlySpan<byte> sessionKey, byte label)
        {
            var key = new byte[sessionKey.Length + 1];
            sessionKey.CopyTo(key);
            key[sessionKey.Length] = label;
            return key;
        }

        /// <inheritdoc/>
        public ValueTask ConnectAsync(CancellationToken cancellationToken = default)
            => _inner.ConnectAsync(cancellationToken);

        /// <inheritdoc/>
        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int read = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read > 0)
            {
                Span<byte> slice = buffer.Span.Slice(0, read);
                _receiveCipher.Process(slice, slice);   // RC4 in place: decrypt exactly the bytes that arrived
            }
            return read;
        }

        /// <inheritdoc/>
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            // RC4 must advance over exactly the bytes written, in order, so we encrypt into a fresh buffer per write.
            var encrypted = new byte[buffer.Length];
            _sendCipher.Process(buffer.Span, encrypted);
            return _inner.WriteAsync(encrypted, cancellationToken);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
