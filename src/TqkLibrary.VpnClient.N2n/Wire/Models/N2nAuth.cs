using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// n2n v3 authentication block (<c>n2n_auth_t</c>): a 16-bit scheme, a 16-bit token length and the token bytes.
    /// On the wire it is <c>scheme(2 BE) ‖ token_size(2 BE) ‖ token(token_size)</c>. For a community with no
    /// user/password auth the edge sends scheme <c>n2n_auth_simple_id</c> (1) with a 16-byte challenge token; this
    /// project sends scheme 1 by default so the supernode accepts the registration.
    /// </summary>
    public sealed class N2nAuth
    {
        /// <summary>Maximum token length n2n v3 accepts (<c>N2N_AUTH_MAX_TOKEN_SIZE</c>).</summary>
        public const int MaxTokenSize = 48;

        /// <summary>n2n_auth_none — no authentication token.</summary>
        public const ushort SchemeNone = 0;

        /// <summary>n2n_auth_simple_id — a plain (challenge) token, the default for password-less communities.</summary>
        public const ushort SchemeSimpleId = 1;

        /// <summary>n2n_auth_user_password — user/password derived token.</summary>
        public const ushort SchemeUserPassword = 2;

        /// <summary>Authentication scheme (<see cref="SchemeNone"/>/<see cref="SchemeSimpleId"/>/<see cref="SchemeUserPassword"/>).</summary>
        public ushort Scheme { get; init; } = SchemeSimpleId;

        /// <summary>Token bytes (length encoded as token_size; ≤ <see cref="MaxTokenSize"/>).</summary>
        public byte[] Token { get; init; } = Array.Empty<byte>();

        /// <summary>Encoded length: 2 (scheme) + 2 (token_size) + token length.</summary>
        public int EncodedSize => 4 + Token.Length;

        /// <summary>A simple-id auth with a fresh 16-byte random challenge token (matches n2n's default for no-password communities).</summary>
        public static N2nAuth SimpleIdRandom()
        {
            byte[] token = new byte[16];
#if NET6_0_OR_GREATER
            System.Security.Cryptography.RandomNumberGenerator.Fill(token);
#else
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(token);
#endif
            return new N2nAuth { Scheme = SchemeSimpleId, Token = token };
        }

        /// <summary>Writes this auth block to <paramref name="dst"/> and returns the byte count written.</summary>
        public int Write(Span<byte> dst)
        {
            if (Token.Length > MaxTokenSize) throw new InvalidOperationException("auth token exceeds N2N_AUTH_MAX_TOKEN_SIZE");
            BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(0, 2), Scheme);
            BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(2, 2), (ushort)Token.Length);
            Token.AsSpan().CopyTo(dst.Slice(4, Token.Length));
            return EncodedSize;
        }

        /// <summary>Reads an auth block from <paramref name="src"/>, advancing <paramref name="offset"/> past it.</summary>
        public static N2nAuth Read(ReadOnlySpan<byte> src, ref int offset)
        {
            ushort scheme = BinaryPrimitives.ReadUInt16BigEndian(src.Slice(offset, 2));
            ushort size = BinaryPrimitives.ReadUInt16BigEndian(src.Slice(offset + 2, 2));
            if (size > MaxTokenSize) throw new FormatException("auth token_size exceeds maximum");
            byte[] token = src.Slice(offset + 4, size).ToArray();
            offset += 4 + size;
            return new N2nAuth { Scheme = scheme, Token = token };
        }
    }
}
