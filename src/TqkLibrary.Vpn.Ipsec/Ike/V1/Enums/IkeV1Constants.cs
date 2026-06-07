namespace TqkLibrary.Vpn.Ipsec.Ike.V1.Enums
{
    /// <summary>ISAKMP header flag bits (RFC 2408 §3.1).</summary>
    [System.Flags]
    public enum IsakmpFlags : byte
    {
        /// <summary>No flags.</summary>
        None = 0,

        /// <summary>Payloads after the header are encrypted.</summary>
        Encryption = 0x01,

        /// <summary>Commit bit.</summary>
        Commit = 0x02,

        /// <summary>Authentication-only bit.</summary>
        Authentication = 0x04,
    }

    /// <summary>
    /// IKEv1 numeric constants: the IPsec DOI, protocol/transform ids, and the SA attribute classes/values used to
    /// build Phase 1 (ISAKMP SA) and Phase 2 (IPsec/ESP SA) proposals (RFC 2407/2408/2409, RFC 3947).
    /// </summary>
    public static class IkeV1Constants
    {
        /// <summary>IPsec DOI.</summary>
        public const uint IpsecDoi = 1;

        /// <summary>SIT_IDENTITY_ONLY situation.</summary>
        public const uint SituationIdentityOnly = 1;

        /// <summary>Protocol IDs in proposals (RFC 2407 §4.4.1).</summary>
        public static class Protocol
        {
            /// <summary>ISAKMP (Phase 1).</summary>
            public const byte Isakmp = 1;

            /// <summary>ESP (Phase 2).</summary>
            public const byte Esp = 3;
        }

        /// <summary>Phase 1 transform id (the only one): KEY_IKE.</summary>
        public const byte TransformKeyIke = 1;

        /// <summary>Phase 2 ESP transform ids (RFC 2407 §4.4.4).</summary>
        public static class EspTransform
        {
            /// <summary>ESP_3DES.</summary>
            public const byte TripleDes = 3;

            /// <summary>ESP_AES (CBC; key length carried as an attribute).</summary>
            public const byte Aes = 12;
        }

        /// <summary>Phase 1 (ISAKMP) SA attribute classes (RFC 2409 Appendix A).</summary>
        public static class Phase1Attribute
        {
            /// <summary>Encryption Algorithm.</summary>
            public const ushort Encryption = 1;
            /// <summary>Hash Algorithm.</summary>
            public const ushort Hash = 2;
            /// <summary>Authentication Method.</summary>
            public const ushort AuthMethod = 3;
            /// <summary>Group Description (D-H).</summary>
            public const ushort Group = 4;
            /// <summary>Life Type.</summary>
            public const ushort LifeType = 11;
            /// <summary>Life Duration.</summary>
            public const ushort LifeDuration = 12;
            /// <summary>Key Length (bits, for AES).</summary>
            public const ushort KeyLength = 14;
        }

        /// <summary>Phase 1 encryption algorithm values.</summary>
        public static class Phase1Encryption
        {
            /// <summary>3DES-CBC.</summary>
            public const ushort TripleDes = 5;
            /// <summary>AES-CBC.</summary>
            public const ushort AesCbc = 7;
        }

        /// <summary>Hash algorithm values (shared by Phase 1 Hash and Phase 2 Auth where applicable).</summary>
        public static class HashAlgorithm
        {
            /// <summary>MD5.</summary>
            public const ushort Md5 = 1;
            /// <summary>SHA-1.</summary>
            public const ushort Sha1 = 2;
            /// <summary>SHA2-256.</summary>
            public const ushort Sha2_256 = 4;
        }

        /// <summary>Authentication method values.</summary>
        public static class AuthMethod
        {
            /// <summary>Pre-shared key.</summary>
            public const ushort PreSharedKey = 1;
        }

        /// <summary>Diffie-Hellman group values (match the MODP group numbers).</summary>
        public static class Group
        {
            /// <summary>MODP-1024 (group 2).</summary>
            public const ushort Modp1024 = 2;
            /// <summary>MODP-2048 (group 14).</summary>
            public const ushort Modp2048 = 14;
        }

        /// <summary>Life type values.</summary>
        public static class LifeType
        {
            /// <summary>Seconds.</summary>
            public const ushort Seconds = 1;
        }

        /// <summary>Phase 2 (IPsec) SA attribute classes (RFC 2407 §4.5).</summary>
        public static class Phase2Attribute
        {
            /// <summary>SA Life Type.</summary>
            public const ushort LifeType = 1;
            /// <summary>SA Life Duration.</summary>
            public const ushort LifeDuration = 2;
            /// <summary>Group Description (PFS).</summary>
            public const ushort Group = 3;
            /// <summary>Encapsulation Mode.</summary>
            public const ushort EncapsulationMode = 4;
            /// <summary>Authentication Algorithm.</summary>
            public const ushort AuthAlgorithm = 5;
            /// <summary>Key Length (bits).</summary>
            public const ushort KeyLength = 6;
        }

        /// <summary>Encapsulation mode values (RFC 2407 + RFC 3947).</summary>
        public static class EncapsulationMode
        {
            /// <summary>Tunnel.</summary>
            public const ushort Tunnel = 1;
            /// <summary>Transport.</summary>
            public const ushort Transport = 2;
            /// <summary>UDP-Encapsulated-Tunnel (RFC 3947).</summary>
            public const ushort UdpTunnel = 3;
            /// <summary>UDP-Encapsulated-Transport (RFC 3947).</summary>
            public const ushort UdpTransport = 4;
        }

        /// <summary>Phase 2 ESP authentication algorithm values (RFC 2407 §4.5).</summary>
        public static class AuthAlgorithm
        {
            /// <summary>HMAC-SHA1-96.</summary>
            public const ushort HmacSha1 = 2;
            /// <summary>HMAC-SHA2-256-128.</summary>
            public const ushort HmacSha2_256 = 5;
        }
    }
}
