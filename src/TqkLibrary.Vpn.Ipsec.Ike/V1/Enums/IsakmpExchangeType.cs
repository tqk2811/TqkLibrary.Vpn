namespace TqkLibrary.Vpn.Ipsec.Ike.V1.Enums
{
    /// <summary>IKEv1 exchange types (RFC 2408 §3.1, RFC 2409).</summary>
    public enum IsakmpExchangeType : byte
    {
        /// <summary>Base exchange.</summary>
        Base = 1,

        /// <summary>Identity Protection — Main Mode (Phase 1).</summary>
        MainMode = 2,

        /// <summary>Authentication Only.</summary>
        AuthenticationOnly = 3,

        /// <summary>Aggressive Mode (Phase 1).</summary>
        Aggressive = 4,

        /// <summary>Informational.</summary>
        Informational = 5,

        /// <summary>Quick Mode (Phase 2).</summary>
        QuickMode = 32,

        /// <summary>New Group Mode.</summary>
        NewGroup = 33,
    }
}
