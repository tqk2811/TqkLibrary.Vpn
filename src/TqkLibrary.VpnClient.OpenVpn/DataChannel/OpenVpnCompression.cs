namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// Data-channel compression framing (V2.f) — the client only ever offers the <em>stub</em> (no actual
    /// compression), so this adds/strips the framing byte around a tunnelled packet but never compresses. An incoming
    /// packet that is genuinely compressed is rejected (we negotiated no compression). Sits between the IP packet and
    /// <see cref="OpenVpnDataChannel"/>: <see cref="WrapOutgoing"/> before <c>Protect</c>, <see cref="TryUnwrapIncoming"/>
    /// after <c>TryUnprotect</c>.
    /// </summary>
    public sealed class OpenVpnCompression
    {
        const byte NoCompressByte = 0xFA;       // comp-lzo: uncompressed marker
        const byte LzoCompressByte = 0x66;      // comp-lzo: LZO-compressed (unsupported here)
        const byte Lz4CompressByte = 0x69;      // comp: LZ4-compressed (unsupported here)
        const byte StubV2Indicator = 0x50;      // compress stub-v2: escape indicator byte
        const byte StubV2Uncompressed = 0x00;   // compress stub-v2: uncompressed op

        /// <summary>The framing the peer negotiated.</summary>
        public enum Mode
        {
            /// <summary>No compression framing — packets pass through unchanged.</summary>
            None,
            /// <summary><c>comp-lzo</c> / <c>comp-lzo no</c>: a 1-byte prefix on every packet.</summary>
            CompLzo,
            /// <summary><c>compress stub-v2</c>: zero overhead unless the first byte collides with the indicator.</summary>
            StubV2,
        }

        readonly Mode _mode;

        /// <summary>Creates the codec for a given framing mode.</summary>
        public OpenVpnCompression(Mode mode) => _mode = mode;

        /// <summary>The active framing mode.</summary>
        public Mode Framing => _mode;

        /// <summary>Maps a pushed compression directive (<see cref="OpenVpnPushReply.Compression"/>) to a framing mode.</summary>
        public static OpenVpnCompression FromPushReply(OpenVpnPushReply reply)
        {
            string? c = reply?.Compression?.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(c)) return new OpenVpnCompression(Mode.None);
            if (c!.StartsWith("comp-lzo")) return new OpenVpnCompression(Mode.CompLzo);     // incl. "comp-lzo no"
            if (c.StartsWith("compress")) return new OpenVpnCompression(Mode.StubV2);       // incl. "compress"/"compress stub-v2"
            return new OpenVpnCompression(Mode.None);
        }

        /// <summary>Adds the (no-compression) framing for an outgoing tunnelled packet.</summary>
        public byte[] WrapOutgoing(ReadOnlySpan<byte> ipPacket)
        {
            switch (_mode)
            {
                case Mode.CompLzo:
                    {
                        byte[] outp = new byte[ipPacket.Length + 1];
                        outp[0] = NoCompressByte;
                        ipPacket.CopyTo(outp.AsSpan(1));
                        return outp;
                    }
                case Mode.StubV2:
                    // Zero overhead unless the first byte collides with the indicator (IP packets never start with 0x50).
                    if (ipPacket.Length > 0 && ipPacket[0] == StubV2Indicator)
                    {
                        byte[] esc = new byte[ipPacket.Length + 2];
                        esc[0] = StubV2Indicator;
                        esc[1] = StubV2Uncompressed;
                        ipPacket.CopyTo(esc.AsSpan(2));
                        return esc;
                    }
                    return ipPacket.ToArray();
                default:
                    return ipPacket.ToArray();
            }
        }

        /// <summary>
        /// Strips the framing from an incoming packet. Returns false if the packet is genuinely compressed (which we do
        /// not support, having negotiated the stub) or the framing is malformed.
        /// </summary>
        public bool TryUnwrapIncoming(ReadOnlySpan<byte> framed, out byte[] ipPacket)
        {
            ipPacket = Array.Empty<byte>();
            switch (_mode)
            {
                case Mode.CompLzo:
                    if (framed.Length < 1) return false;
                    if (framed[0] == LzoCompressByte || framed[0] == Lz4CompressByte) return false; // compressed ⇒ unsupported
                    if (framed[0] != NoCompressByte) return false; // comp-lzo always carries the 1-byte marker
                    ipPacket = framed.Slice(1).ToArray();
                    return true;
                case Mode.StubV2:
                    if (framed.Length == 0) { ipPacket = Array.Empty<byte>(); return true; }
                    if (framed[0] != StubV2Indicator) { ipPacket = framed.ToArray(); return true; } // common: no overhead
                    if (framed.Length < 2 || framed[1] != StubV2Uncompressed) return false;          // compressed/malformed
                    ipPacket = framed.Slice(2).ToArray();
                    return true;
                default:
                    ipPacket = framed.ToArray();
                    return true;
            }
        }
    }
}
