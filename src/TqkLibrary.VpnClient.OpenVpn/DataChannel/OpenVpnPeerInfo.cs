using System.Text;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// Builds the OpenVPN peer-info block (the <c>IV_*</c> lines) the client sends inside its key-method-2 message.
    /// The server reads <c>IV_PROTO</c> (capabilities) and <c>IV_CIPHERS</c> (the NCP cipher list) to choose the data
    /// cipher, then echoes its pick in PUSH_REPLY (<c>cipher …</c>). See <see cref="OpenVpnDataCipher"/> for the
    /// advertised list and <see cref="OpenVpnKeyMethod2.BuildClientMessage"/> for where the block is carried.
    /// </summary>
    public static class OpenVpnPeerInfo
    {
        /// <summary><c>IV_PROTO</c> bit: the peer understands P_DATA_V2 (peer-id data packets).</summary>
        public const int IvProtoDataV2 = 1 << 1;

        /// <summary><c>IV_PROTO</c> bit: the peer will send PUSH_REQUEST proactively after connecting.</summary>
        public const int IvProtoRequestPush = 1 << 2;

        /// <summary>
        /// Builds the peer-info string (newline-separated <c>IV_*</c> lines). <paramref name="ciphers"/> is the NCP
        /// list (default <see cref="OpenVpnDataCipher.AdvertisedList"/>); <paramref name="ivProto"/> is the capability
        /// bitmask (default DATA_V2 | REQUEST_PUSH).
        /// </summary>
        public static string Build(string? ciphers = null, int ivProto = IvProtoDataV2 | IvProtoRequestPush,
            string version = "2.6.0", string platform = "dotnet")
        {
            ciphers ??= OpenVpnDataCipher.AdvertisedList;
            var sb = new StringBuilder();
            sb.Append("IV_VER=").Append(version).Append('\n');
            sb.Append("IV_PLAT=").Append(platform).Append('\n');
            sb.Append("IV_PROTO=").Append(ivProto).Append('\n');
            sb.Append("IV_NCP=2\n");
            sb.Append("IV_CIPHERS=").Append(ciphers).Append('\n');
            return sb.ToString();
        }
    }
}
