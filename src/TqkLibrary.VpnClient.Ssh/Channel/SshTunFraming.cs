using TqkLibrary.VpnClient.Ssh.Channel.Enums;

namespace TqkLibrary.VpnClient.Ssh.Channel
{
    /// <summary>
    /// Encapsulates / decapsulates a layer-3 IP packet for a <c>tun@openssh.com</c> channel (OpenSSH PROTOCOL §2.3). The
    /// SSH_MSG_CHANNEL_DATA "string" already carries its own uint32 length prefix (the SSH wire <c>string</c> encoding),
    /// so inside it the layer-3 payload is simply:
    /// <code>uint32 address_family || ip_packet</code>
    /// where <c>address_family</c> is <see cref="SshTunAddressFamily"/> (2 = IPv4, 24 = IPv6) chosen from the IP version
    /// nibble and a bare IP packet (no link header) follows. (The PROTOCOL text's leading "uint32 packet length" is the
    /// SSH string length prefix itself — what OpenSSH's <c>sys_tun_*filter</c> actually prepends/strips on the wire is the
    /// 4-byte address family only; this was confirmed live against OpenSSH on Linux. This is a pure codec.
    /// </summary>
    public static class SshTunFraming
    {
        /// <summary>The fixed framing overhead inside the channel-data string: the 4-byte address-family field.</summary>
        public const int Overhead = 4;

        /// <summary>
        /// Wraps a bare IP packet into the tun@openssh.com channel-data payload. The address family is taken from the IP
        /// version nibble (4 → IPv4, 6 → IPv6); anything else defaults to IPv4.
        /// </summary>
        public static byte[] Encapsulate(ReadOnlySpan<byte> ipPacket)
        {
            SshTunAddressFamily af = (ipPacket.Length > 0 && (ipPacket[0] >> 4) == 6) ? SshTunAddressFamily.Inet6 : SshTunAddressFamily.Inet;

            byte[] data = new byte[4 + ipPacket.Length];
            WriteUInt32(data, 0, (uint)af);
            ipPacket.CopyTo(data.AsSpan(4));
            return data;
        }

        /// <summary>
        /// Extracts the bare IP packet from a tun@openssh.com channel-data payload (<c>address_family</c> + the IP packet).
        /// Returns false (with an empty result) when the framing is too short to hold the 4-byte address family.
        /// </summary>
        public static bool TryDecapsulate(ReadOnlySpan<byte> channelData, out ReadOnlySpan<byte> ipPacket, out SshTunAddressFamily addressFamily)
        {
            ipPacket = default;
            addressFamily = SshTunAddressFamily.Inet;
            if (channelData.Length < 4) return false;

            addressFamily = (SshTunAddressFamily)ReadUInt32(channelData, 0);
            ipPacket = channelData.Slice(4); // the rest is the bare IP packet
            return true;
        }

        static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        static uint ReadUInt32(ReadOnlySpan<byte> buffer, int offset)
            => (uint)((buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);
    }
}
