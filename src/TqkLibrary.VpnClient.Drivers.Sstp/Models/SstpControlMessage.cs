using TqkLibrary.VpnClient.Drivers.Sstp.Enums;

namespace TqkLibrary.VpnClient.Drivers.Sstp.Models
{
    /// <summary>A parsed SSTP control message: a type plus its attributes.</summary>
    public sealed class SstpControlMessage
    {
        /// <summary>Creates a control message.</summary>
        public SstpControlMessage(SstpMessageType type, List<SstpAttribute> attributes)
        {
            MessageType = type;
            Attributes = attributes;
        }

        /// <summary>The control message type.</summary>
        public SstpMessageType MessageType { get; }

        /// <summary>The attributes carried by this message.</summary>
        public List<SstpAttribute> Attributes { get; }

        /// <summary>Returns the first attribute with the given id, or null.</summary>
        public SstpAttribute? Find(SstpAttributeId id)
        {
            foreach (SstpAttribute attribute in Attributes)
                if (attribute.Id == (byte)id)
                    return attribute;
            return null;
        }
    }
}
