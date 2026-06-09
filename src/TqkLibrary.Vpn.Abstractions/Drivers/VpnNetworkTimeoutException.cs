namespace TqkLibrary.Vpn.Abstractions.Drivers
{
    /// <summary>
    /// Thrown when a handshake step gets no reply within its timeout (e.g. the IKE gateway never answers, or TLS
    /// never completes) — a transport/reachability problem rather than a rejection. This is NOT used for caller
    /// cancellation: an <see cref="OperationCanceledException"/> from the caller's token propagates unchanged.
    /// </summary>
    public sealed class VpnNetworkTimeoutException : VpnConnectionException
    {
        /// <summary>Creates the exception with a default message.</summary>
        public VpnNetworkTimeoutException() : base("The VPN gateway did not respond within the timeout.")
        {
        }

        /// <summary>Creates the exception with a message.</summary>
        public VpnNetworkTimeoutException(string message) : base(message)
        {
        }

        /// <summary>Creates the exception with a message and the underlying cause.</summary>
        public VpnNetworkTimeoutException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
