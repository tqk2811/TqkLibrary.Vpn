namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Eap
{
    /// <summary>Outcome of feeding one inbound EAP packet to an EAP method state machine.</summary>
    public enum EapResult
    {
        /// <summary>A response was produced; keep exchanging EAP packets.</summary>
        Continue,

        /// <summary>EAP authentication succeeded (terminal EAP-Success seen); the MSK is available.</summary>
        Success,

        /// <summary>EAP authentication failed (EAP-Failure, malformed packet, or verification mismatch).</summary>
        Failed,
    }
}
