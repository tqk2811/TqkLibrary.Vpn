namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Eap
{
    /// <summary>EAP packet Code field (RFC 3748 §4).</summary>
    public enum EapCode : byte
    {
        /// <summary>No/empty packet.</summary>
        None = 0,

        /// <summary>Request (authenticator → peer).</summary>
        Request = 1,

        /// <summary>Response (peer → authenticator).</summary>
        Response = 2,

        /// <summary>Success — EAP authentication succeeded.</summary>
        Success = 3,

        /// <summary>Failure — EAP authentication failed.</summary>
        Failure = 4,
    }
}
