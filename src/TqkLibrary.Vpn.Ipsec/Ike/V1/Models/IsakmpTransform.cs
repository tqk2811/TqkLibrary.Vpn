namespace TqkLibrary.Vpn.Ipsec.Ike.V1.Models
{
    /// <summary>An ISAKMP transform (RFC 2408 §3.6): a transform id plus its SA attributes.</summary>
    public sealed class IsakmpTransform
    {
        /// <summary>Transform number (1-based within a proposal).</summary>
        public byte Number { get; set; } = 1;

        /// <summary>Transform id (KEY_IKE for Phase 1; ESP_AES/ESP_3DES for Phase 2).</summary>
        public byte TransformId { get; set; }

        /// <summary>The attributes (algorithm choices, key length, lifetime…).</summary>
        public List<IsakmpAttribute> Attributes { get; } = new();

        /// <summary>Creates a transform with the given number/id.</summary>
        public IsakmpTransform() { }

        /// <summary>Creates a transform with the given number/id.</summary>
        public IsakmpTransform(byte number, byte transformId)
        {
            Number = number;
            TransformId = transformId;
        }

        /// <summary>Adds an attribute and returns this transform for chaining.</summary>
        public IsakmpTransform With(IsakmpAttribute attribute)
        {
            Attributes.Add(attribute);
            return this;
        }
    }

    /// <summary>An ISAKMP proposal (RFC 2408 §3.5): a protocol + SPI + a set of transforms.</summary>
    public sealed class IsakmpProposal
    {
        /// <summary>Proposal number.</summary>
        public byte Number { get; set; } = 1;

        /// <summary>Protocol id (ISAKMP for Phase 1, ESP for Phase 2).</summary>
        public byte ProtocolId { get; set; }

        /// <summary>The SPI (empty for Phase 1 ISAKMP; 4 bytes for Phase 2 ESP).</summary>
        public byte[] Spi { get; set; } = Array.Empty<byte>();

        /// <summary>The transforms offered/selected.</summary>
        public List<IsakmpTransform> Transforms { get; } = new();
    }
}
