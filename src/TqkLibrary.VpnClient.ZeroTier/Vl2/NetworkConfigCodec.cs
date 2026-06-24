using System.Buffers.Binary;
using System.Collections.Generic;
using TqkLibrary.VpnClient.ZeroTier.Vl1;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl2
{
    /// <summary>
    /// Builds the body of a VL1 <c>NETWORK_CONFIG_REQUEST</c> and decodes the controller's reply (either an
    /// <c>OK(NETWORK_CONFIG_REQUEST)</c> or a pushed <c>NETWORK_CONFIG</c>). The request body is
    /// <c>networkId(8 BE) || dictLen(2 BE) || metadataDictionary</c>; the reply carries
    /// <c>networkId(8 BE) || dictLen(2 BE) || configDictionary</c> (a single chunk — large multi-chunk configs are out of
    /// scope and reported as a failed decode). The config dictionary is parsed with <see cref="ZeroTierDictionary"/> and
    /// projected onto a <see cref="ZeroTierNetworkConfig"/>.
    /// </summary>
    public sealed class NetworkConfigCodec
    {
        // Dictionary keys used by a ZeroTier controller's network config (NetworkConfig::toDictionary).
        const string KeyStaticIps = "I";       // packed InetAddresses, prefix length in the port field
        const string KeyRoutes = "RT";          // packed (target, via, flags(2), metric(2)) entries
        const string KeyMtu = "mtu";
        const string KeyComNew = "C";           // certificate of membership (current)
        const string KeyComLegacy = "com";      // certificate of membership (legacy)
        const string KeyName = "n";

        readonly InetAddressCodec _inetCodec = new InetAddressCodec();

        /// <summary>
        /// Serialises a NETWORK_CONFIG_REQUEST body. <paramref name="metadata"/> is the optional request metadata
        /// dictionary (a minimal/empty dictionary is accepted by a controller); pass null for an empty dictionary.
        /// </summary>
        public byte[] EncodeRequest(NetworkId network, ZeroTierDictionary? metadata = null)
        {
            byte[] dict = (metadata ?? new ZeroTierDictionary()).Serialize();
            byte[] body = new byte[NetworkId.SizeInBytes + 2 + dict.Length];
            int o = 0;
            network.Write(body.AsSpan(o, NetworkId.SizeInBytes));
            o += NetworkId.SizeInBytes;
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), (ushort)dict.Length);
            o += 2;
            dict.CopyTo(body.AsSpan(o));
            return body;
        }

        /// <summary>
        /// Decodes a single-chunk network config from a <c>networkId(8) || dictLen(2 BE) || dict</c> body. This is the
        /// payload of an <c>OK(NETWORK_CONFIG_REQUEST)</c> (after the OK common header) or of a pushed
        /// <c>NETWORK_CONFIG</c>. Returns false on a truncated buffer or a multi-chunk config (dictLen does not cover the
        /// remaining bytes), which the driver reports as an unsupported (too-large) config.
        /// </summary>
        public bool TryDecodeConfig(ReadOnlySpan<byte> body, out ZeroTierNetworkConfig config)
        {
            config = new ZeroTierNetworkConfig();
            if (body.Length < NetworkId.SizeInBytes + 2) return false;

            int o = 0;
            var network = NetworkId.Read(body.Slice(o, NetworkId.SizeInBytes));
            o += NetworkId.SizeInBytes;
            int dictLen = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(o, 2));
            o += 2;
            if (dictLen == 0 || body.Length - o < dictLen) return false;

            var dict = ZeroTierDictionary.Deserialize(body.Slice(o, dictLen));
            config.Network = network;
            config.AssignedAddresses = ParseInetList(dict.GetBytes(KeyStaticIps));
            config.Routes = ParseRoutes(dict.GetBytes(KeyRoutes));
            config.CertificateOfMembership = dict.GetBytes(KeyComNew) ?? dict.GetBytes(KeyComLegacy);
            config.Name = dict.GetString(KeyName);
            if (dict.TryGetUInt64(KeyMtu, out ulong mtu) && mtu > 0 && mtu <= 0xFFFF) config.Mtu = (int)mtu;
            return true;
        }

        // Read a back-to-back run of InetAddresses (no count prefix — each self-describes its length).
        List<InetAddressValue> ParseInetList(byte[]? blob)
        {
            var list = new List<InetAddressValue>();
            if (blob is null) return list;
            int o = 0;
            while (o < blob.Length)
            {
                if (!_inetCodec.TryDecode(blob.AsSpan(o), out var value, out int consumed) || consumed == 0) break;
                if (!value.IsNil) list.Add(value);
                o += consumed;
            }
            return list;
        }

        // Each route is target:InetAddress || via:InetAddress || flags(2 BE) || metric(2 BE).
        List<(InetAddressValue, InetAddressValue)> ParseRoutes(byte[]? blob)
        {
            var list = new List<(InetAddressValue, InetAddressValue)>();
            if (blob is null) return list;
            int o = 0;
            while (o < blob.Length)
            {
                if (!_inetCodec.TryDecode(blob.AsSpan(o), out var target, out int tc) || tc == 0) break;
                o += tc;
                if (!_inetCodec.TryDecode(blob.AsSpan(o), out var via, out int vc) || vc == 0) break;
                o += vc;
                if (blob.Length - o < 4) break;     // flags(2) + metric(2)
                o += 4;
                list.Add((target, via));
            }
            return list;
        }
    }
}
