namespace TqkLibrary.VpnClient.Abstractions.Drivers
{
    /// <summary>
    /// Thrown when the server actively refuses the session at the protocol level — e.g. an SSTP Call-Connect-Nak /
    /// Call-Abort, a non-200 SSTP HTTP handshake, or an IKE Quick Mode that yields no SA. Distinct from an
    /// authentication failure (credentials were not necessarily wrong) and from a network timeout (the server did reply).
    /// </summary>
    public sealed class VpnServerRejectedException : VpnConnectionException
    {
        /// <summary>Creates the exception with a message.</summary>
        public VpnServerRejectedException(string message) : base(message)
        {
        }

        /// <summary>Creates the exception with a message and the underlying cause.</summary>
        public VpnServerRejectedException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
