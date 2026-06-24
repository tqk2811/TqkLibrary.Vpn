namespace TqkLibrary.VpnClient.Tailscale
{
    /// <summary>
    /// Tailscale ts2021 protocol constants. The capability version is a monotonically increasing integer the client
    /// advertises in <c>RegisterRequest.Version</c> / <c>MapRequest.Version</c> and in <c>/key?v=</c>. Crucially it is
    /// also the value carried in the ts2021 <b>initiation frame header</b> and the Noise prologue: Headscale reads the
    /// frame's protocol-version field as the client's <c>CapabilityVersion</c> and rejects the Noise upgrade when it is
    /// below <c>MinSupportedCapabilityVersion</c> (113 at time of writing — Tailscale v1.80). So the control-protocol
    /// version is <b>not</b> a separate small constant; it equals the capability version.
    /// </summary>
    public static class TailscaleCapability
    {
        /// <summary>
        /// The capability version advertised to the control server — in <c>/key?v=</c>, in the JSON
        /// <c>Version</c> fields, and in the ts2021 initiation frame header + Noise prologue. Chosen at the
        /// Headscale-supported minimum (113 = Tailscale v1.80) so the Noise upgrade is accepted without depending on
        /// features of newer clients.
        /// </summary>
        public const int CapabilityVersion = 113;

        /// <summary>
        /// The ts2021 control-protocol version put in the initiation frame header and the Noise prologue. Headscale
        /// treats this as the client's capability version, so it must equal <see cref="CapabilityVersion"/>.
        /// </summary>
        public const int ControlProtocolVersion = CapabilityVersion;
    }
}
