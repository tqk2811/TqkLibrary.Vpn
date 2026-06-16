using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Builds and reads the DHCP option field that follows the BOOTP header (RFC 2131 §3 / RFC 2132): the 4-byte magic
    /// cookie <c>0x63825363</c> then a sequence of TLV options <c>(code, len, value…)</c> terminated by option 255.
    /// Only the codes the L2.5 client needs are modeled — message-type (53), requested-IP (50), server-id (54),
    /// lease-time (51), subnet-mask (1), router (3) and DNS (6); other codes are skipped on read. Mirrors the static,
    /// allocation-light codec style of <see cref="ArpPacket"/> and <see cref="Icmpv6Ndisc"/> — no instance state.
    /// </summary>
    public static class DhcpV4Options
    {
        /// <summary>The 4-byte DHCP magic cookie that introduces the option field (RFC 2131 §3, value 99.130.83.99).</summary>
        public const uint MagicCookie = 0x63825363;

        /// <summary>Option 53 — DHCP Message Type (RFC 2132 §9.6).</summary>
        public const byte CodeMessageType = 53;

        /// <summary>Option 50 — Requested IP Address (RFC 2132 §9.1), sent in a REQUEST.</summary>
        public const byte CodeRequestedIp = 50;

        /// <summary>Option 54 — Server Identifier (RFC 2132 §9.7).</summary>
        public const byte CodeServerId = 54;

        /// <summary>Option 51 — IP Address Lease Time in seconds (RFC 2132 §9.2).</summary>
        public const byte CodeLeaseTime = 51;

        /// <summary>Option 1 — Subnet Mask (RFC 2132 §3.3).</summary>
        public const byte CodeSubnetMask = 1;

        /// <summary>Option 3 — Router / default gateway list (RFC 2132 §3.5).</summary>
        public const byte CodeRouter = 3;

        /// <summary>Option 6 — Domain Name Server list (RFC 2132 §3.8).</summary>
        public const byte CodeDnsServer = 6;

        /// <summary>Option 55 — Parameter Request List (RFC 2132 §9.8), the options a client asks the server to send.</summary>
        public const byte CodeParameterRequestList = 55;

        /// <summary>Option 12 — Host Name (RFC 2132 §3.14).</summary>
        public const byte CodeHostName = 12;

        /// <summary>Option 61 — Client Identifier (RFC 2132 §9.14).</summary>
        public const byte CodeClientId = 61;

        /// <summary>The pad option (RFC 2132 §3.1): a single zero byte with no length/value, skipped on read.</summary>
        public const byte CodePad = 0;

        /// <summary>The end option (RFC 2132 §3.2): terminates the option field.</summary>
        public const byte CodeEnd = 255;

        // ---- DHCP message types (RFC 2131 §3.1, option 53 values) ----

        /// <summary>DHCPDISCOVER (1).</summary>
        public const byte MessageDiscover = 1;

        /// <summary>DHCPOFFER (2).</summary>
        public const byte MessageOffer = 2;

        /// <summary>DHCPREQUEST (3).</summary>
        public const byte MessageRequest = 3;

        /// <summary>DHCPDECLINE (4).</summary>
        public const byte MessageDecline = 4;

        /// <summary>DHCPACK (5).</summary>
        public const byte MessageAck = 5;

        /// <summary>DHCPNAK (6).</summary>
        public const byte MessageNak = 6;

        /// <summary>DHCPRELEASE (7).</summary>
        public const byte MessageRelease = 7;

        /// <summary>Writes the magic cookie (4 bytes) at the start of the option field and returns the next offset.</summary>
        public static int WriteMagicCookie(byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(MagicCookie >> 24);
            buffer[offset + 1] = (byte)((MagicCookie >> 16) & 0xFF);
            buffer[offset + 2] = (byte)((MagicCookie >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(MagicCookie & 0xFF);
            return offset + 4;
        }

        /// <summary>Writes one TLV option (code, length, value) and returns the next offset.</summary>
        public static int WriteOption(byte[] buffer, int offset, byte code, ReadOnlySpan<byte> value)
        {
            buffer[offset] = code;
            buffer[offset + 1] = (byte)value.Length;
            value.CopyTo(buffer.AsSpan(offset + 2, value.Length));
            return offset + 2 + value.Length;
        }

        /// <summary>Writes a single-byte option (e.g. message-type) and returns the next offset.</summary>
        public static int WriteOption(byte[] buffer, int offset, byte code, byte value)
        {
            buffer[offset] = code;
            buffer[offset + 1] = 1;
            buffer[offset + 2] = value;
            return offset + 3;
        }

        /// <summary>Writes an IPv4-address option (e.g. requested-IP/server-id) and returns the next offset.</summary>
        public static int WriteOption(byte[] buffer, int offset, byte code, IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("DHCP option carries an IPv4 address.", nameof(address));
            return WriteOption(buffer, offset, code, address.GetAddressBytes());
        }

        /// <summary>Writes the end option (255) and returns the next offset.</summary>
        public static int WriteEnd(byte[] buffer, int offset)
        {
            buffer[offset] = CodeEnd;
            return offset + 1;
        }

        /// <summary>
        /// Verifies the magic cookie at the start of the option field. <paramref name="options"/> must begin with the
        /// 4-byte cookie (i.e. the slice after the 236-byte BOOTP header).
        /// </summary>
        public static bool HasMagicCookie(ReadOnlySpan<byte> options)
            => options.Length >= 4
               && (((uint)options[0] << 24) | ((uint)options[1] << 16) | ((uint)options[2] << 8) | options[3]) == MagicCookie;

        /// <summary>
        /// Reads the DHCP message-type (option 53) from the option field (which still includes the magic cookie),
        /// or <c>0</c> if the cookie is missing or the option is absent.
        /// </summary>
        public static byte ReadMessageType(ReadOnlySpan<byte> options)
            => TryGetOption(options, CodeMessageType, out ReadOnlySpan<byte> value) && value.Length >= 1 ? value[0] : (byte)0;

        /// <summary>Reads an IPv4-address option (e.g. server-id 54, subnet-mask 1) if present and 4 bytes long.</summary>
        public static IPAddress? ReadAddress(ReadOnlySpan<byte> options, byte code)
            => TryGetOption(options, code, out ReadOnlySpan<byte> value) && value.Length == 4
                ? new IPAddress(value.ToArray())
                : null;

        /// <summary>Reads a list-of-IPv4-addresses option (e.g. router 3, DNS 6) — value length must be a multiple of 4.</summary>
        public static IReadOnlyList<IPAddress> ReadAddresses(ReadOnlySpan<byte> options, byte code)
        {
            var list = new List<IPAddress>();
            if (TryGetOption(options, code, out ReadOnlySpan<byte> value) && value.Length % 4 == 0)
            {
                for (int i = 0; i + 4 <= value.Length; i += 4)
                    list.Add(new IPAddress(value.Slice(i, 4).ToArray()));
            }
            return list;
        }

        /// <summary>Reads the lease-time option (51, big-endian uint32 seconds), or <c>0</c> if absent/malformed.</summary>
        public static uint ReadLeaseTime(ReadOnlySpan<byte> options)
            => TryGetOption(options, CodeLeaseTime, out ReadOnlySpan<byte> value) && value.Length == 4
                ? ((uint)value[0] << 24) | ((uint)value[1] << 16) | ((uint)value[2] << 8) | value[3]
                : 0;

        /// <summary>
        /// Finds option <paramref name="code"/> in the option field (after the 4-byte magic cookie), returning its value
        /// slice. Pad (0) options are skipped; End (255) stops the scan; a malformed/truncated option ends the scan.
        /// </summary>
        public static bool TryGetOption(ReadOnlySpan<byte> options, byte code, out ReadOnlySpan<byte> value)
        {
            value = default;
            if (!HasMagicCookie(options))
                return false;
            int pos = 4;   // skip the magic cookie
            while (pos < options.Length)
            {
                byte c = options[pos];
                if (c == CodePad) { pos++; continue; }
                if (c == CodeEnd) return false;
                if (pos + 2 > options.Length) return false;       // need code + length
                int len = options[pos + 1];
                if (pos + 2 + len > options.Length) return false; // truncated value
                if (c == code)
                {
                    value = options.Slice(pos + 2, len);
                    return true;
                }
                pos += 2 + len;
            }
            return false;
        }
    }
}
