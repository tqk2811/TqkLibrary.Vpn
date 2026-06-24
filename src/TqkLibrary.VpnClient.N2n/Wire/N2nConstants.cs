namespace TqkLibrary.VpnClient.N2n.Wire
{
    /// <summary>
    /// Fixed sizes and protocol constants shared across the n2n v3 wire codec (matching the C constants in
    /// <c>n2n_define.h</c>). Pure data — no behavior.
    /// </summary>
    public static class N2nConstants
    {
        /// <summary>On-wire protocol version (<c>N2N_PKT_VERSION</c>).</summary>
        public const byte PktVersion = 3;

        /// <summary>Default time-to-live for relayed packets (<c>N2N_DEFAULT_TTL</c>).</summary>
        public const byte DefaultTtl = 2;

        /// <summary>Community name field length (<c>N2N_COMMUNITY_SIZE</c>) — null-padded ASCII.</summary>
        public const int CommunitySize = 20;

        /// <summary>MAC address length (<c>N2N_MAC_SIZE</c>).</summary>
        public const int MacSize = 6;

        /// <summary>Device description field length (<c>N2N_DESC_SIZE</c>) — null-padded ASCII.</summary>
        public const int DescSize = 16;

        /// <summary>Cookie length on the wire (<c>n2n_cookie_t</c> = uint32_t).</summary>
        public const int CookieSize = 4;

        /// <summary>Common header length: version(1) + ttl(1) + flags(2) + community(20).</summary>
        public const int CommonHeaderSize = 24;
    }
}
