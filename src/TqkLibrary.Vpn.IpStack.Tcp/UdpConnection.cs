using System.Net;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>
    /// A userspace UDP socket bound to one local port on the tunnel address. Datagrams are sent immediately; inbound
    /// datagrams matching the local port are queued and surfaced by <see cref="ReceiveAsync"/>. No connection state —
    /// the remote endpoint is supplied per send and reported per receive.
    /// </summary>
    public sealed class UdpConnection
    {
        readonly IPAddress _localAddress;
        readonly Action<byte[]> _sendIp;
        readonly object _sync = new();
        readonly Queue<Datagram> _inbound = new();
        TaskCompletionSource<bool>? _waiter;
        ushort _identification;

        internal UdpConnection(IPAddress localAddress, ushort localPort, Action<byte[]> sendIp)
        {
            _localAddress = localAddress;
            LocalPort = localPort;
            _sendIp = sendIp;
        }

        /// <summary>The bound local UDP port.</summary>
        public ushort LocalPort { get; }

        /// <summary>Sends <paramref name="data"/> to the given remote endpoint as one UDP datagram.</summary>
        public void SendTo(IPAddress remoteAddress, ushort remotePort, ReadOnlySpan<byte> data)
        {
            byte[] udp = UdpDatagram.Build(_localAddress, remoteAddress, LocalPort, remotePort, data);
            byte[] ip = Ipv4.Build(_localAddress, remoteAddress, Ipv4.ProtocolUdp, udp, _identification++);
            _sendIp(ip);
        }

        /// <summary>Receives the next inbound datagram, returning its data and source endpoint.</summary>
        public async Task<UdpReceiveResult> ReceiveAsync(CancellationToken cancellationToken = default)
        {
            while (true)
            {
                Task wait;
                lock (_sync)
                {
                    if (_inbound.Count > 0)
                    {
                        Datagram d = _inbound.Dequeue();
                        return new UdpReceiveResult(d.Data, d.RemoteAddress, d.RemotePort);
                    }
                    _waiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    wait = _waiter.Task;
                }
                using (cancellationToken.Register(static w => ((TaskCompletionSource<bool>)w!).TrySetResult(true), _waiter))
                    await wait.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        internal void OnDatagram(IPAddress remoteAddress, ushort remotePort, byte[] payload)
        {
            TaskCompletionSource<bool>? waiter;
            lock (_sync)
            {
                _inbound.Enqueue(new Datagram(payload, remoteAddress, remotePort));
                waiter = _waiter;
                _waiter = null;
            }
            waiter?.TrySetResult(true);
        }

        readonly struct Datagram
        {
            public Datagram(byte[] data, IPAddress remoteAddress, ushort remotePort)
            {
                Data = data; RemoteAddress = remoteAddress; RemotePort = remotePort;
            }
            public byte[] Data { get; }
            public IPAddress RemoteAddress { get; }
            public ushort RemotePort { get; }
        }
    }

    /// <summary>The data and source endpoint of a received UDP datagram.</summary>
    public readonly struct UdpReceiveResult
    {
        /// <summary>Creates a result.</summary>
        public UdpReceiveResult(byte[] data, IPAddress remoteAddress, ushort remotePort)
        {
            Data = data; RemoteAddress = remoteAddress; RemotePort = remotePort;
        }

        /// <summary>The datagram payload.</summary>
        public byte[] Data { get; }

        /// <summary>The source address.</summary>
        public IPAddress RemoteAddress { get; }

        /// <summary>The source port.</summary>
        public ushort RemotePort { get; }
    }
}
