using System.Buffers.Binary;
using System.Text;
using TqkLibrary.VpnClient.N2n.Transform.Interfaces;
using TqkLibrary.VpnClient.N2n.Wire;
using TqkLibrary.VpnClient.N2n.Wire.Enums;
using TqkLibrary.VpnClient.N2n.Wire.Models;

namespace TqkLibrary.VpnClient.N2n
{
    /// <summary>
    /// Encodes and decodes n2n v3 control/data messages (cleartext-header form — header encryption off). Every message
    /// is the 24-byte <see cref="N2nCommonHeader"/> followed by the type-specific body, all big-endian. The codec drives
    /// the message models in <see cref="Wire.Models"/>; the caller supplies the community/MAC/cookie. PACKET payloads
    /// pass through an <see cref="IN2nTransform"/> so the inner Ethernet frame is (optionally) encrypted.
    /// <para>
    /// Stateless and reusable; the driver (V.7.4 phase b) wraps the UDP transport and supernode/edge state around it.
    /// </para>
    /// </summary>
    public sealed class N2nPacketCodec
    {
        // Scratch big enough for any control message we build (frames are sized to the payload at call time).
        const int MaxControlSize = 512;

        // ---- REGISTER_SUPER ---------------------------------------------------------------------------------

        /// <summary>Encodes a REGISTER_SUPER message (edge → supernode) for the given community.</summary>
        public byte[] EncodeRegisterSuper(string community, N2nRegisterSuper body, byte ttl = N2nConstants.DefaultTtl)
        {
            if (body is null) throw new ArgumentNullException(nameof(body));
            N2nFlags flags = body.Sock is not null ? N2nFlags.Socket : N2nFlags.None;
            byte[] buf = new byte[MaxControlSize];
            int off = WriteCommon(buf, community, N2nPacketType.RegisterSuper, flags, ttl);

            off += WriteUInt32(buf.AsSpan(off), body.Cookie);
            off += WriteMac(buf.AsSpan(off), body.EdgeMac);
            if (body.Sock is not null) off += body.Sock.Write(buf.AsSpan(off));
            off += body.DevAddr.Write(buf.AsSpan(off));
            off += WriteDesc(buf.AsSpan(off), body.DevDesc);
            off += body.Auth.Write(buf.AsSpan(off));
            off += WriteUInt32(buf.AsSpan(off), body.KeyTime);
            return buf.AsSpan(0, off).ToArray();
        }

        /// <summary>Decodes a REGISTER_SUPER message. Returns false if it is not a well-formed REGISTER_SUPER.</summary>
        public bool TryDecodeRegisterSuper(ReadOnlySpan<byte> packet, out N2nCommonHeader header, out N2nRegisterSuper body)
        {
            body = null!;
            if (!TryReadCommon(packet, N2nPacketType.RegisterSuper, out header, out int off)) return false;
            try
            {
                uint cookie = ReadUInt32(packet, ref off);
                byte[] mac = ReadMac(packet, ref off);
                N2nSock? sock = (header.Flags & N2nFlags.Socket) != 0 ? N2nSock.Read(packet, ref off) : null;
                N2nIpSubnet devAddr = N2nIpSubnet.Read(packet, ref off);
                string desc = ReadDesc(packet, ref off);
                N2nAuth auth = N2nAuth.Read(packet, ref off);
                uint keyTime = ReadUInt32(packet, ref off);
                body = new N2nRegisterSuper
                {
                    Cookie = cookie, EdgeMac = mac, Sock = sock, DevAddr = devAddr,
                    DevDesc = desc, Auth = auth, KeyTime = keyTime,
                };
                return true;
            }
            catch (Exception ex) when (ex is FormatException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                return false;
            }
        }

        // ---- REGISTER_SUPER_ACK -----------------------------------------------------------------------------

        /// <summary>Encodes a REGISTER_SUPER_ACK message (supernode → edge).</summary>
        public byte[] EncodeRegisterSuperAck(string community, N2nRegisterSuperAck body, byte ttl = N2nConstants.DefaultTtl)
        {
            if (body is null) throw new ArgumentNullException(nameof(body));
            byte[] buf = new byte[MaxControlSize];
            int off = WriteCommon(buf, community, N2nPacketType.RegisterSuperAck, N2nFlags.FromSupernode, ttl);

            off += WriteUInt32(buf.AsSpan(off), body.Cookie);
            off += WriteMac(buf.AsSpan(off), body.SrcMac);
            off += body.DevAddr.Write(buf.AsSpan(off));
            off += WriteUInt16(buf.AsSpan(off), body.Lifetime);
            off += body.Sock.Write(buf.AsSpan(off));
            off += body.Auth.Write(buf.AsSpan(off));
            buf[off++] = body.NumSn;
            foreach (var sn in body.ExtraSupernodes) off += sn.Write(buf.AsSpan(off));
            off += WriteUInt32(buf.AsSpan(off), body.KeyTime);
            return buf.AsSpan(0, off).ToArray();
        }

        /// <summary>Decodes a REGISTER_SUPER_ACK message. Returns false if it is not well-formed.</summary>
        public bool TryDecodeRegisterSuperAck(ReadOnlySpan<byte> packet, out N2nCommonHeader header, out N2nRegisterSuperAck body)
        {
            body = null!;
            if (!TryReadCommon(packet, N2nPacketType.RegisterSuperAck, out header, out int off)) return false;
            try
            {
                uint cookie = ReadUInt32(packet, ref off);
                byte[] mac = ReadMac(packet, ref off);
                N2nIpSubnet devAddr = N2nIpSubnet.Read(packet, ref off);
                ushort lifetime = ReadUInt16(packet, ref off);
                N2nSock sock = N2nSock.Read(packet, ref off);
                N2nAuth auth = N2nAuth.Read(packet, ref off);
                byte numSn = packet[off++];
                var extra = new N2nSock[numSn];
                for (int i = 0; i < numSn; i++) extra[i] = N2nSock.Read(packet, ref off);
                uint keyTime = off + 4 <= packet.Length ? ReadUInt32(packet, ref off) : 0;
                body = new N2nRegisterSuperAck
                {
                    Cookie = cookie, SrcMac = mac, DevAddr = devAddr, Lifetime = lifetime,
                    Sock = sock, Auth = auth, NumSn = numSn, ExtraSupernodes = extra, KeyTime = keyTime,
                };
                return true;
            }
            catch (Exception ex) when (ex is FormatException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                return false;
            }
        }

        // ---- REGISTER / REGISTER_ACK ------------------------------------------------------------------------

        /// <summary>Encodes an edge↔edge REGISTER message.</summary>
        public byte[] EncodeRegister(string community, N2nRegister body, byte ttl = N2nConstants.DefaultTtl)
        {
            if (body is null) throw new ArgumentNullException(nameof(body));
            N2nFlags flags = body.Sock is not null ? N2nFlags.Socket : N2nFlags.None;
            byte[] buf = new byte[MaxControlSize];
            int off = WriteCommon(buf, community, N2nPacketType.Register, flags, ttl);

            off += WriteUInt32(buf.AsSpan(off), body.Cookie);
            off += WriteMac(buf.AsSpan(off), body.SrcMac);
            off += WriteMac(buf.AsSpan(off), body.DstMac);
            if (body.Sock is not null) off += body.Sock.Write(buf.AsSpan(off));
            off += body.DevAddr.Write(buf.AsSpan(off));
            off += WriteDesc(buf.AsSpan(off), body.DevDesc);
            return buf.AsSpan(0, off).ToArray();
        }

        /// <summary>Decodes an edge↔edge REGISTER message.</summary>
        public bool TryDecodeRegister(ReadOnlySpan<byte> packet, out N2nCommonHeader header, out N2nRegister body)
        {
            body = null!;
            if (!TryReadCommon(packet, N2nPacketType.Register, out header, out int off)) return false;
            try
            {
                uint cookie = ReadUInt32(packet, ref off);
                byte[] src = ReadMac(packet, ref off);
                byte[] dst = ReadMac(packet, ref off);
                N2nSock? sock = (header.Flags & N2nFlags.Socket) != 0 ? N2nSock.Read(packet, ref off) : null;
                N2nIpSubnet devAddr = N2nIpSubnet.Read(packet, ref off);
                string desc = ReadDesc(packet, ref off);
                body = new N2nRegister { Cookie = cookie, SrcMac = src, DstMac = dst, Sock = sock, DevAddr = devAddr, DevDesc = desc };
                return true;
            }
            catch (Exception ex) when (ex is FormatException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                return false;
            }
        }

        /// <summary>Encodes an edge↔edge REGISTER_ACK message.</summary>
        public byte[] EncodeRegisterAck(string community, N2nRegisterAck body, byte ttl = N2nConstants.DefaultTtl)
        {
            if (body is null) throw new ArgumentNullException(nameof(body));
            N2nFlags flags = body.Sock is not null ? N2nFlags.Socket : N2nFlags.None;
            byte[] buf = new byte[MaxControlSize];
            int off = WriteCommon(buf, community, N2nPacketType.RegisterAck, flags, ttl);

            off += WriteUInt32(buf.AsSpan(off), body.Cookie);
            off += WriteMac(buf.AsSpan(off), body.SrcMac);
            off += WriteMac(buf.AsSpan(off), body.DstMac);
            if (body.Sock is not null) off += body.Sock.Write(buf.AsSpan(off));
            return buf.AsSpan(0, off).ToArray();
        }

        /// <summary>Decodes an edge↔edge REGISTER_ACK message.</summary>
        public bool TryDecodeRegisterAck(ReadOnlySpan<byte> packet, out N2nCommonHeader header, out N2nRegisterAck body)
        {
            body = null!;
            if (!TryReadCommon(packet, N2nPacketType.RegisterAck, out header, out int off)) return false;
            try
            {
                uint cookie = ReadUInt32(packet, ref off);
                byte[] src = ReadMac(packet, ref off);
                byte[] dst = ReadMac(packet, ref off);
                N2nSock? sock = (header.Flags & N2nFlags.Socket) != 0 ? N2nSock.Read(packet, ref off) : null;
                body = new N2nRegisterAck { Cookie = cookie, SrcMac = src, DstMac = dst, Sock = sock };
                return true;
            }
            catch (Exception ex) when (ex is FormatException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                return false;
            }
        }

        // ---- PEER_INFO --------------------------------------------------------------------------------------

        /// <summary>Decodes a PEER_INFO message (supernode → edge). The numeric fields are read; trailing version bytes are ignored.</summary>
        public bool TryDecodePeerInfo(ReadOnlySpan<byte> packet, out N2nCommonHeader header, out N2nPeerInfo body)
        {
            body = null!;
            if (!TryReadCommon(packet, N2nPacketType.PeerInfo, out header, out int off)) return false;
            try
            {
                ushort aflags = ReadUInt16(packet, ref off);
                byte[] mac = ReadMac(packet, ref off);
                N2nSock sock = N2nSock.Read(packet, ref off);
                N2nSock preferred = N2nSock.Read(packet, ref off);
                uint load = ReadUInt32(packet, ref off);
                uint uptime = off + 4 <= packet.Length ? ReadUInt32(packet, ref off) : 0;
                body = new N2nPeerInfo { AFlags = aflags, Mac = mac, Sock = sock, PreferredSock = preferred, Load = load, Uptime = uptime };
                return true;
            }
            catch (Exception ex) when (ex is FormatException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                return false;
            }
        }

        // ---- PACKET (data) ----------------------------------------------------------------------------------

        /// <summary>
        /// Encodes a PACKET (data) message carrying an Ethernet frame. The frame in <paramref name="body"/>.Payload is
        /// run through <paramref name="transform"/> (whose <see cref="IN2nTransform.Id"/> is stamped into the body).
        /// </summary>
        public byte[] EncodePacket(string community, N2nPacket body, IN2nTransform transform, byte ttl = N2nConstants.DefaultTtl)
        {
            if (body is null) throw new ArgumentNullException(nameof(body));
            if (transform is null) throw new ArgumentNullException(nameof(transform));
            byte[] enc = transform.Encode(body.Payload);

            N2nFlags flags = body.Sock is not null ? N2nFlags.Socket : N2nFlags.None;
            int headerLen = N2nConstants.CommonHeaderSize + 6 + 6 + (body.Sock?.EncodedSize ?? 0) + 2;
            byte[] buf = new byte[headerLen + enc.Length];
            int off = WriteCommon(buf, community, N2nPacketType.Packet, flags, ttl);

            off += WriteMac(buf.AsSpan(off), body.SrcMac);
            off += WriteMac(buf.AsSpan(off), body.DstMac);
            if (body.Sock is not null) off += body.Sock.Write(buf.AsSpan(off));
            buf[off++] = body.Compression;
            buf[off++] = (byte)transform.Id;
            enc.CopyTo(buf.AsSpan(off));
            return buf;
        }

        /// <summary>
        /// Decodes a PACKET message, applying <paramref name="transform"/> (must match the body's transform id) to
        /// recover the Ethernet frame into <see cref="N2nPacket.Payload"/>.
        /// </summary>
        public bool TryDecodePacket(ReadOnlySpan<byte> packet, IN2nTransform transform, out N2nCommonHeader header, out N2nPacket body)
        {
            body = null!;
            if (!TryReadCommon(packet, N2nPacketType.Packet, out header, out int off)) return false;
            try
            {
                byte[] src = ReadMac(packet, ref off);
                byte[] dst = ReadMac(packet, ref off);
                N2nSock? sock = (header.Flags & N2nFlags.Socket) != 0 ? N2nSock.Read(packet, ref off) : null;
                byte compression = packet[off++];
                var transformId = (N2nTransformId)packet[off++];
                byte[] enc = packet.Slice(off).ToArray();
                byte[] frame = transform is not null ? transform.Decode(enc) : enc;
                body = new N2nPacket
                {
                    SrcMac = src, DstMac = dst, Sock = sock, Compression = compression,
                    Transform = transformId, Payload = frame,
                };
                return true;
            }
            catch (Exception ex) when (ex is FormatException or ArgumentOutOfRangeException or IndexOutOfRangeException or ArgumentException)
            {
                return false;
            }
        }

        // ---- header encryption (-H) -------------------------------------------------------------------------

        /// <summary>
        /// The length of a PACKET's n2n header (everything before the transform-protected payload): the common header
        /// plus src/dst MAC, the optional socket, and the compression + transform bytes. This is the
        /// <c>header_len</c> n2n header-encrypts on a data PACKET (the payload stays under the transform).
        /// </summary>
        public static int PacketHeaderLength(bool hasSocket, int socketEncodedSize)
            => N2nConstants.CommonHeaderSize + 6 + 6 + (hasSocket ? socketEncodedSize : 0) + 2;

        /// <summary>
        /// Encrypts the n2n header of <paramref name="datagram"/> in place with header encryption (<c>-H</c>). For a
        /// control message pass <paramref name="headerLen"/> = the whole datagram length; for a data PACKET pass the n2n
        /// header length (see <see cref="PacketHeaderLength"/>) so the transform-protected payload is left intact.
        /// Returns the same array (mutated) for chaining. No-op when <paramref name="headerEnc"/> is null.
        /// </summary>
        public static byte[] EncryptHeader(byte[] datagram, int headerLen, N2nHeaderEncryption? headerEnc, ulong stamp)
        {
            if (headerEnc is null) return datagram;
            Span<byte> random = stackalloc byte[4];
#if NET6_0_OR_GREATER
            System.Security.Cryptography.RandomNumberGenerator.Fill(random);
#else
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                byte[] tmp = new byte[4]; rng.GetBytes(tmp); tmp.CopyTo(random);
            }
#endif
            headerEnc.Encrypt(datagram, headerLen, datagram.Length, stamp, random);
            return datagram;
        }

        /// <summary>
        /// Tries to decrypt the n2n header of <paramref name="datagram"/> in place (header encryption, <c>-H</c>). On
        /// success the cleartext header is restored so the normal Try* decoders can run; returns false if the magic /
        /// checksum does not match (wrong community, not header-encrypted, or tampered). A null
        /// <paramref name="headerEnc"/> is treated as "no header encryption" and returns true unchanged.
        /// </summary>
        public static bool TryDecryptHeader(Span<byte> datagram, N2nHeaderEncryption? headerEnc, out ulong stamp)
        {
            stamp = 0;
            if (headerEnc is null) return true;
            return headerEnc.Decrypt(datagram, datagram.Length, out stamp);
        }

        // ---- peek -------------------------------------------------------------------------------------------

        /// <summary>Reads only the common header so a dispatcher can branch on <see cref="N2nCommonHeader.PacketType"/>.</summary>
        public bool TryPeekHeader(ReadOnlySpan<byte> packet, out N2nCommonHeader header)
        {
            header = null!;
            if (packet.Length < N2nConstants.CommonHeaderSize) return false;
            int off = 0;
            header = N2nCommonHeader.Read(packet, ref off);
            return true;
        }

        // ---- helpers ----------------------------------------------------------------------------------------

        static int WriteCommon(Span<byte> buf, string community, N2nPacketType type, N2nFlags flags, byte ttl)
        {
            var header = new N2nCommonHeader { Ttl = ttl, PacketType = type, Flags = flags, Community = community };
            return header.Write(buf);
        }

        static bool TryReadCommon(ReadOnlySpan<byte> packet, N2nPacketType expected, out N2nCommonHeader header, out int offset)
        {
            header = null!;
            offset = 0;
            if (packet.Length < N2nConstants.CommonHeaderSize) return false;
            header = N2nCommonHeader.Read(packet, ref offset);
            return header.PacketType == expected;
        }

        static int WriteMac(Span<byte> dst, byte[] mac)
        {
            if (mac is null || mac.Length != N2nConstants.MacSize) throw new ArgumentException("MAC must be 6 bytes.");
            mac.AsSpan().CopyTo(dst.Slice(0, N2nConstants.MacSize));
            return N2nConstants.MacSize;
        }

        static byte[] ReadMac(ReadOnlySpan<byte> src, ref int offset)
        {
            byte[] mac = src.Slice(offset, N2nConstants.MacSize).ToArray();
            offset += N2nConstants.MacSize;
            return mac;
        }

        static int WriteDesc(Span<byte> dst, string desc)
        {
            dst.Slice(0, N2nConstants.DescSize).Clear();
            byte[] bytes = Encoding.ASCII.GetBytes(desc ?? string.Empty);
            int n = Math.Min(bytes.Length, N2nConstants.DescSize);
            bytes.AsSpan(0, n).CopyTo(dst);
            return N2nConstants.DescSize;
        }

        static string ReadDesc(ReadOnlySpan<byte> src, ref int offset)
        {
            ReadOnlySpan<byte> field = src.Slice(offset, N2nConstants.DescSize);
            int len = field.IndexOf((byte)0);
            if (len < 0) len = field.Length;
            offset += N2nConstants.DescSize;
            return Encoding.ASCII.GetString(field.Slice(0, len).ToArray());
        }

        static int WriteUInt16(Span<byte> dst, ushort v) { BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(0, 2), v); return 2; }
        static int WriteUInt32(Span<byte> dst, uint v) { BinaryPrimitives.WriteUInt32BigEndian(dst.Slice(0, 4), v); return 4; }

        static ushort ReadUInt16(ReadOnlySpan<byte> src, ref int off) { ushort v = BinaryPrimitives.ReadUInt16BigEndian(src.Slice(off, 2)); off += 2; return v; }
        static uint ReadUInt32(ReadOnlySpan<byte> src, ref int off) { uint v = BinaryPrimitives.ReadUInt32BigEndian(src.Slice(off, 4)); off += 4; return v; }
    }
}
