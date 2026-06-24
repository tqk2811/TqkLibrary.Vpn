using System.Security.Cryptography;
using System.Text;

namespace TqkLibrary.VpnClient.Drivers.Tinc.DataChannel
{
    /// <summary>
    /// A tinc node identifier — the first 6 bytes of <c>SHA512(node_name)</c> (tinc's <c>node_add</c> in <c>node.c</c>:
    /// <c>sha512(name, strlen(name), buf); memcpy(&amp;n-&gt;id, buf, sizeof(node_id_t))</c>, where <c>node_id_t</c> is a
    /// 6-byte array). It stamps the source/destination of a UDP data datagram so the peer can route it without first
    /// confirming our UDP address — the receiver demuxes by these ids (<c>handle_incoming_vpn_packet</c>). Pure/stateless,
    /// so a static codec is appropriate.
    /// </summary>
    public static class TincNodeId
    {
        /// <summary>Computes the 6-byte node id for <paramref name="nodeName"/> (ASCII, as tinc hashes the raw name bytes).</summary>
        public static byte[] Compute(string nodeName)
        {
            if (nodeName is null) throw new ArgumentNullException(nameof(nodeName));
            byte[] nameBytes = Encoding.ASCII.GetBytes(nodeName);
            byte[] hash;
            using (var sha = SHA512.Create())
                hash = sha.ComputeHash(nameBytes);
            byte[] id = new byte[TincDriverConstants.NodeIdLength];
            Array.Copy(hash, id, TincDriverConstants.NodeIdLength);
            return id;
        }
    }
}
