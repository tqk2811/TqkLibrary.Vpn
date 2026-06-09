namespace TqkLibrary.Vpn.Abstractions.Drivers
{
    /// <summary>
    /// Base type for failures while establishing or maintaining a VPN connection. Catch this to handle any
    /// connection error generically; catch a derived type (<see cref="VpnAuthenticationException"/>,
    /// <see cref="VpnServerRejectedException"/>, <see cref="VpnNetworkTimeoutException"/>) to react to a specific cause.
    /// </summary>
    public class VpnConnectionException : Exception
    {
        /// <summary>Creates the exception with a message.</summary>
        public VpnConnectionException(string message) : base(message)
        {
        }

        /// <summary>Creates the exception with a message and the underlying cause.</summary>
        public VpnConnectionException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
