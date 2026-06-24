namespace TqkLibrary.VpnClient.Nebula.Packet.Enums
{
    /// <summary>
    /// The Nebula packet type carried in the low nibble of the first header byte (header.go <c>MessageType</c>).
    /// </summary>
    public enum NebulaMessageType
    {
        /// <summary>Noise IX handshake packet.</summary>
        Handshake = 0,

        /// <summary>Encrypted data (transport) packet.</summary>
        Message = 1,

        /// <summary>Receive-error / tunnel-not-found notification.</summary>
        RecvError = 2,

        /// <summary>Lighthouse discovery message (sent inside an established tunnel).</summary>
        LightHouse = 3,

        /// <summary>Tunnel liveness test.</summary>
        Test = 4,

        /// <summary>Tunnel close notification.</summary>
        CloseTunnel = 5,

        /// <summary>Control-plane message (relays, etc.).</summary>
        Control = 6,
    }
}
