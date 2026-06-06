using System.Net;
using System.Net.Sockets;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Ipsec.Esp;
using TqkLibrary.Vpn.Ipsec.Ike.V1;
using TqkLibrary.Vpn.L2tp;
using TqkLibrary.Vpn.Ppp;
using TqkLibrary.Vpn.Ppp.Auth;
using TqkLibrary.Vpn.Transport.Udp;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>
    /// A complete L2TP/IPsec client: IKEv1 Main Mode + Quick Mode (PSK) over UDP/500→4500 NAT-T, an ESP transport-mode
    /// data plane, an L2TP tunnel/session over UDP/1701, and a PPP session (MS-CHAPv2) that yields the assigned IP.
    /// After <see cref="ConnectAsync"/> the tunnel carries IP traffic via <see cref="PacketChannel"/>.
    /// </summary>
    public sealed class L2tpIpsecConnection : IDisposable
    {
        readonly string _host;
        readonly byte[] _preSharedKey;
        readonly uint _magic;

        NatTraversalChannel? _natt;
        IpsecL2tpTransport? _dataTransport;
        L2tpClient? _l2tp;
        PppEngine? _ppp;
        CancellationTokenSource? _loopCts;
        TaskCompletionSource<byte[]>? _ikeWaiter;
        volatile bool _espActive;

        /// <summary>Creates a connection to the given L2TP/IPsec gateway with the IPsec pre-shared key.</summary>
        public L2tpIpsecConnection(string host, byte[] preSharedKey, uint magic = 0x4D2A3B1C)
        {
            _host = host;
            _preSharedKey = preSharedKey;
            _magic = magic;
        }

        /// <summary>The L3 packet channel (valid after a successful connect).</summary>
        public IPacketChannel PacketChannel => _ppp!.PacketChannel;

        /// <summary>The IP address assigned by the server via IPCP.</summary>
        public IPAddress AssignedAddress => _ppp!.AssignedAddress;

        /// <summary>The DNS server pushed by IPCP, if any.</summary>
        public IPAddress? AssignedDns => _ppp!.AssignedDns;

        /// <summary>Runs the full handshake and returns once PPP/IPCP has assigned an address.</summary>
        public async Task ConnectAsync(string userName, string password, CancellationToken cancellationToken = default)
        {
            IPAddress serverIp = await ResolveAsync(_host).ConfigureAwait(false);
            _natt = new NatTraversalChannel(serverIp, NatTraversal.IkePort);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _ = Task.Run(() => ReceiveLoopAsync(_loopCts.Token));

            var ike = new IkeV1Client(_preSharedKey, IPAddress.Any, serverIp);

            // Phase 1 — Main Mode (messages 1-4 on UDP/500).
            ike.ProcessMainMode2(await ExchangeIkeAsync(ike.BuildMainMode1(), cancellationToken).ConfigureAwait(false));
            ike.ProcessMainMode4(await ExchangeIkeAsync(ike.BuildMainMode3(IPAddress.Any, serverIp), cancellationToken).ConfigureAwait(false));

            // NAT-T detected → move to UDP/4500 for the encrypted MM5/MM6 and all of Quick Mode + ESP.
            _natt.SwitchToNatTPort();
            if (!ike.ProcessMainMode6(await ExchangeIkeAsync(ike.BuildMainMode5(), cancellationToken).ConfigureAwait(false)))
                throw new IOException("IKEv1 Phase 1 authentication failed (PSK / HASH_R mismatch).");

            // Phase 2 — Quick Mode.
            if (!ike.ProcessQuickMode2(await ExchangeIkeAsync(ike.BuildQuickMode1(), cancellationToken).ConfigureAwait(false)))
                throw new IOException("IKEv1 Quick Mode failed (no ESP SA).");
            await _natt.SendIkeAsync(ike.BuildQuickMode3()).ConfigureAwait(false); // QM3 has no reply

            // ESP data plane + L2TP + PPP.
            EspSession esp = BuildEspSession(ike);
            _dataTransport = new IpsecL2tpTransport(esp, datagram => _natt.SendEspAsync(datagram));
            _espActive = true;

            _l2tp = new L2tpClient(_dataTransport);
            await _l2tp.ConnectAsync(cancellationToken).ConfigureAwait(false);

            var pppChannel = new L2tpPppFrameChannel(_l2tp);
            var authenticator = new MsChapV2Authenticator(userName, password);
            _ppp = new PppEngine(pppChannel, _magic, IPAddress.Any, authenticator: authenticator);

            var linkUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _ppp.LinkUp += () => linkUp.TrySetResult(true);
            _ppp.AuthFailed += () => linkUp.TrySetException(new IOException("PPP MS-CHAPv2 authentication failed."));
            _ppp.Start();

            await WaitAsync(linkUp.Task, cancellationToken).ConfigureAwait(false);
        }

        static EspSession BuildEspSession(IkeV1Client ike)
        {
            IkeV1Phase2Keys keys = ike.CreatePhase2Keys();
            EspCipherSuite outbound = EspCipherSuite.AesCbcHmacSha1(keys.OutboundEncryption, keys.OutboundIntegrity);
            EspCipherSuite inbound = EspCipherSuite.AesCbcHmacSha1(keys.InboundEncryption, keys.InboundIntegrity);
            return new EspSession(ToSpi(ike.ChildOutboundSpi), outbound, ToSpi(ike.ChildInboundSpi), inbound);
        }

        async Task<byte[]> ExchangeIkeAsync(byte[] request, CancellationToken cancellationToken)
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                _ikeWaiter = waiter;
                await _natt!.SendIkeAsync(request).ConfigureAwait(false);

                Task completed = await Task.WhenAny(waiter.Task, Task.Delay(2500, cancellationToken)).ConfigureAwait(false);
                if (completed == waiter.Task) return await waiter.Task.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
            throw new TimeoutException("No IKE response from the gateway.");
        }

        async Task ReceiveLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    (NatTPacketKind kind, byte[] payload) = await _natt!.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                    if (kind == NatTPacketKind.Ike)
                        _ikeWaiter?.TrySetResult(payload);
                    else if (kind == NatTPacketKind.Esp && _espActive)
                        _dataTransport?.OnEspPacket(payload);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _ikeWaiter?.TrySetException(ex); }
        }

        static async Task WaitAsync(Task task, CancellationToken cancellationToken)
        {
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                if (await Task.WhenAny(task, cancelled.Task).ConfigureAwait(false) != task)
                    cancellationToken.ThrowIfCancellationRequested();
            }
            await task.ConfigureAwait(false);
        }

        static async Task<IPAddress> ResolveAsync(string host)
        {
            if (IPAddress.TryParse(host, out IPAddress? literal)) return literal;
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
            return addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);
        }

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        /// <inheritdoc/>
        public void Dispose()
        {
            _loopCts?.Cancel();
            _l2tp?.Dispose();
            _ = _natt?.DisposeAsync();
        }
    }
}
