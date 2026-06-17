namespace TqkLibrary.VpnClient.Ethernet
{
    public sealed partial class EthernetSwitch
    {
        /// <summary>
        /// The public handle for an uplink port attached via <see cref="EthernetSwitch.ConnectUplink"/>. Disposing it
        /// detaches the uplink from the switch (unsubscribes its inbound frames and purges the FDB entries that pointed
        /// at it); it never disposes the caller-owned <see cref="IEthernetChannel"/> uplink itself.
        /// </summary>
        public sealed class UplinkPortHandle : IAsyncDisposable
        {
            readonly UplinkPort _port;

            internal UplinkPortHandle(UplinkPort port) => _port = port;

            /// <inheritdoc/>
            public ValueTask DisposeAsync() => _port.DisposeAsync();
        }
    }
}
