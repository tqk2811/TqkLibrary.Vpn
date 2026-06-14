namespace TqkLibrary.VpnClient.Abstractions.Drivers
{
    /// <summary>
    /// Thrown when the server rejects the supplied credentials (e.g. PPP MS-CHAPv2 failure, or an IKE PSK / HASH_R
    /// mismatch). Retrying with the same credentials will not help — surface it to the user to fix username/password/PSK.
    /// </summary>
    public sealed class VpnAuthenticationException : VpnConnectionException
    {
        /// <summary>Creates the exception with a default message.</summary>
        public VpnAuthenticationException() : base("VPN authentication failed (bad username/password or pre-shared key).")
        {
        }

        /// <summary>Creates the exception with a message.</summary>
        public VpnAuthenticationException(string message) : base(message)
        {
        }

        /// <summary>Creates the exception with a message and the underlying cause.</summary>
        public VpnAuthenticationException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
