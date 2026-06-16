using System.Net;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads
{
    /// <summary>
    /// Configuration Payload (CP), RFC 7296 §3.15: the mechanism that pulls a virtual IP, netmask and DNS from the
    /// gateway. Layout: CFG Type(1) | RESERVED(3) | one-or-more <see cref="IkeConfigAttribute"/>. The client sends a
    /// CFG_REQUEST with empty attributes inside IKE_AUTH; the responder answers with a CFG_REPLY carrying the
    /// assigned values.
    /// </summary>
    public sealed class ConfigurationPayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.Configuration;

        /// <summary>Whether this is a REQUEST, REPLY, SET or ACK.</summary>
        public IkeConfigType ConfigType { get; set; } = IkeConfigType.Request;

        /// <summary>The configuration attributes, in order.</summary>
        public List<IkeConfigAttribute> Attributes { get; } = new();

        /// <summary>
        /// Builds a CFG_REQUEST asking for the given attribute types (empty values). Defaults to an IPv4 address +
        /// netmask + DNS — the typical client "give me a virtual IP" request.
        /// </summary>
        public static ConfigurationPayload Request(params IkeConfigAttributeType[] requested)
        {
            if (requested.Length == 0)
                requested = new[]
                {
                    IkeConfigAttributeType.InternalIp4Address,
                    IkeConfigAttributeType.InternalIp4Netmask,
                    IkeConfigAttributeType.InternalIp4Dns,
                };
            var cp = new ConfigurationPayload { ConfigType = IkeConfigType.Request };
            foreach (IkeConfigAttributeType type in requested)
                cp.Attributes.Add(IkeConfigAttribute.Request(type));
            return cp;
        }

        /// <summary>The first INTERNAL_IP4_ADDRESS the responder assigned, or null.</summary>
        public IPAddress? AssignedIp4Address => FirstAddress(IkeConfigAttributeType.InternalIp4Address);

        /// <summary>The first INTERNAL_IP6_ADDRESS the responder assigned (address bytes only), or null.</summary>
        public IPAddress? AssignedIp6Address
        {
            get
            {
                IkeConfigAttribute? attribute = Attributes.FirstOrDefault(a => a.AttributeType == IkeConfigAttributeType.InternalIp6Address);
                // INTERNAL_IP6_ADDRESS is 16 address bytes + a 1-byte prefix length.
                return attribute is { Value.Length: >= 16 } ? new IPAddress(attribute.Value.AsSpan(0, 16).ToArray()) : null;
            }
        }

        /// <summary>Every assigned DNS server (IPv4 and IPv6), in the order the responder listed them.</summary>
        public IReadOnlyList<IPAddress> DnsServers => Attributes
            .Where(a => a.AttributeType is IkeConfigAttributeType.InternalIp4Dns or IkeConfigAttributeType.InternalIp6Dns)
            .Select(a => a.AsIpAddress)
            .Where(ip => ip is not null)
            .Select(ip => ip!)
            .ToArray();

        IPAddress? FirstAddress(IkeConfigAttributeType type)
            => Attributes.FirstOrDefault(a => a.AttributeType == type)?.AsIpAddress;

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            output.Add((byte)ConfigType);
            output.Add(0); output.Add(0); output.Add(0); // RESERVED(3)
            foreach (IkeConfigAttribute attribute in Attributes)
                attribute.Write(output);
        }

        internal static ConfigurationPayload Parse(ReadOnlySpan<byte> body)
        {
            var cp = new ConfigurationPayload();
            if (body.Length < 4) return cp;
            cp.ConfigType = (IkeConfigType)body[0];

            int offset = 4; // CFG Type(1) + RESERVED(3)
            while (offset + 4 <= body.Length)
            {
                int type = IkeBuffer.ReadUInt16(body, offset) & 0x7FFF; // mask the reserved high bit
                int length = IkeBuffer.ReadUInt16(body, offset + 2);
                if (offset + 4 + length > body.Length) break;
                cp.Attributes.Add(new IkeConfigAttribute((IkeConfigAttributeType)type, body.Slice(offset + 4, length).ToArray()));
                offset += 4 + length;
            }
            return cp;
        }
    }
}
