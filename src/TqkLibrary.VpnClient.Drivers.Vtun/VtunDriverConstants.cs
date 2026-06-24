namespace TqkLibrary.VpnClient.Drivers.Vtun
{
    /// <summary>Driver-level constants for the vtun driver (defaults not part of the wire protocol).</summary>
    public static class VtunDriverConstants
    {
        /// <summary>The driver name tag.</summary>
        public const string DriverName = "vtun";

        /// <summary>Default tunnel MTU. vtund's example configs use 1450 (1500 − tun/header headroom).</summary>
        public const int DefaultMtu = 1450;
    }
}
