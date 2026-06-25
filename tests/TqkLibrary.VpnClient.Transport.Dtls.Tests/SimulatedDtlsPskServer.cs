using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Transport.Dtls.Tests
{
    /// <summary>
    /// A throwaway DTLS 1.2 <b>PSK</b> server (BouncyCastle <see cref="DtlsServerProtocol"/> + <see cref="PskTlsServer"/>),
    /// mirroring the modern OpenConnect <c>PSK-NEGOTIATE</c> data path: it runs the server half of a full DTLS 1.2 PSK
    /// handshake over one end of a <see cref="LoopbackDatagramLink"/>, then echoes each inbound datagram. It exists only
    /// to exercise <see cref="OpenConnectDtls12PskClient"/> offline (the library ships a client only). The server
    /// validates the offered PSK identity against the expected one and answers with the shared key.
    /// </summary>
    sealed class SimulatedDtlsPskServer : IDisposable
    {
        readonly IDatagramTransport _transport;
        readonly BcTlsCrypto _crypto;
        readonly byte[] _expectedIdentity;
        readonly byte[] _pskKey;
        readonly Thread _thread;

        /// <summary>The exception that ended the server loop, if any (handshake failure, etc.).</summary>
        public Exception? Failure { get; private set; }

        /// <summary>The PSK identity the client offered (captured during the handshake), for client-side assertions.</summary>
        public byte[]? ObservedIdentity { get; private set; }

        public SimulatedDtlsPskServer(LoopbackDatagramLink.End transport, byte[] expectedIdentity, byte[] pskKey)
        {
            _transport = transport;
            _crypto = new BcTlsCrypto(new SecureRandom());
            _expectedIdentity = expectedIdentity;
            _pskKey = pskKey;
            _thread = new Thread(RunLoop) { IsBackground = true, Name = "dtls-psk-test-server" };
        }

        public void Start() => _thread.Start();

        void RunLoop()
        {
            try
            {
                var protocol = new DtlsServerProtocol();
                var server = new PskEchoServer(_crypto, _expectedIdentity, _pskKey, id => ObservedIdentity = id);
                using var bridge = new ServerDatagramBridge(_transport);
                DtlsTransport dtls = protocol.Accept(server, bridge);
                byte[] buffer = new byte[2048];
                while (true)
                {
                    int read = dtls.Receive(buffer, 0, buffer.Length, 30000);
                    if (read < 0) break;
                    if (read == 0) continue;
                    dtls.Send(buffer, 0, read);
                }
                dtls.Close();
            }
            catch (Exception e) { Failure = e; }
        }

        public void Dispose() { }

        /// <summary>Test sync↔async bridge (a copy of the production bridge; server-only scaffolding).</summary>
        sealed class ServerDatagramBridge : DatagramTransport, IDisposable
        {
            const int MtuLimit = 1500;
            readonly IDatagramTransport _inner;
            readonly BlockingCollection<byte[]> _inbound = new(new ConcurrentQueue<byte[]>());
            readonly CancellationTokenSource _cts = new();
            readonly Task _pump;

            public ServerDatagramBridge(IDatagramTransport inner)
            {
                _inner = inner;
                _pump = Task.Run(() => PumpAsync(_cts.Token));
            }

            async Task PumpAsync(CancellationToken cancellationToken)
            {
                byte[] buffer = new byte[MtuLimit];
                try
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        int read = await _inner.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                        if (read <= 0) continue;
                        _inbound.Add(buffer.AsSpan(0, read).ToArray(), cancellationToken);
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception) { }
                finally { _inbound.CompleteAdding(); }
            }

            public int GetReceiveLimit() => MtuLimit;
            public int GetSendLimit() => MtuLimit;

            public int Receive(byte[] buf, int off, int len, int waitMillis)
            {
                if (!_inbound.TryTake(out byte[]? d, waitMillis)) return -1;
                int n = Math.Min(len, d.Length);
                Buffer.BlockCopy(d, 0, buf, off, n);
                return n;
            }

            public int Receive(Span<byte> buffer, int waitMillis)
            {
                if (!_inbound.TryTake(out byte[]? d, waitMillis)) return -1;
                int n = Math.Min(buffer.Length, d.Length);
                d.AsSpan(0, n).CopyTo(buffer);
                return n;
            }

            public void Send(byte[] buf, int off, int len)
                => _inner.SendAsync(new ReadOnlyMemory<byte>(buf, off, len)).AsTask().GetAwaiter().GetResult();

            public void Send(ReadOnlySpan<byte> buffer) => Send(buffer.ToArray(), 0, buffer.Length);

            public void Close() => Dispose();

            public void Dispose()
            {
                try { _cts.Cancel(); } catch { }
                try { _pump.Wait(2000); } catch { }
                _cts.Dispose();
                _inbound.Dispose();
            }
        }

        /// <summary>DTLS 1.2 PSK server: AES-GCM PSK suites, answering the shared key for the expected identity.</summary>
        sealed class PskEchoServer : PskTlsServer
        {
            public PskEchoServer(BcTlsCrypto crypto, byte[] expectedIdentity, byte[] pskKey, Action<byte[]> onIdentity)
                : base(crypto, new IdentityManager(expectedIdentity, pskKey, onIdentity)) { }

            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

            protected override int[] GetSupportedCipherSuites() => new[]
            {
                CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256,
            };

            sealed class IdentityManager : TlsPskIdentityManager
            {
                readonly byte[] _expectedIdentity;
                readonly byte[] _pskKey;
                readonly Action<byte[]> _onIdentity;

                public IdentityManager(byte[] expectedIdentity, byte[] pskKey, Action<byte[]> onIdentity)
                {
                    _expectedIdentity = expectedIdentity;
                    _pskKey = pskKey;
                    _onIdentity = onIdentity;
                }

                public byte[]? GetHint() => null; // no PSK identity hint (OpenConnect uses none)

                public byte[]? GetPsk(byte[] identity)
                {
                    _onIdentity(identity);
                    // Return the key only for the expected identity; null aborts the handshake otherwise.
                    if (identity.Length != _expectedIdentity.Length) return null;
                    for (int i = 0; i < identity.Length; i++)
                        if (identity[i] != _expectedIdentity[i]) return null;
                    return (byte[])_pskKey.Clone();
                }
            }
        }
    }
}
