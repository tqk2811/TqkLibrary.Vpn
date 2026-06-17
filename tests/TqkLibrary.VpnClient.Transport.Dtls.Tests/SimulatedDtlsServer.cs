using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Transport.Dtls.Tests
{
    /// <summary>
    /// A throwaway DTLS 1.2 <b>server</b> built from BouncyCastle (<see cref="DtlsServerProtocol"/> + a freshly minted
    /// self-signed RSA certificate). It runs the server half of the handshake on a background thread over one end of a
    /// <see cref="LoopbackDatagramLink"/>, then echoes each inbound datagram straight back. The library only ships a
    /// client, so this server role exists solely to exercise the client offline. The generated certificate is exposed so
    /// a test can assert the client's certificate callback observed it.
    /// </summary>
    sealed class SimulatedDtlsServer : IDisposable
    {
        readonly IDatagramTransport _transport;
        readonly BcTlsCrypto _crypto;
        readonly Certificate _certificate;
        readonly AsymmetricKeyParameter _privateKey;
        readonly Thread _thread;

        /// <summary>The DER bytes of the self-signed certificate the server presents (for client-side assertions).</summary>
        public byte[] CertificateDer { get; }

        /// <summary>The exception that ended the server loop, if any (handshake failure, etc.).</summary>
        public Exception? Failure { get; private set; }

        public SimulatedDtlsServer(LoopbackDatagramLink.End transport)
        {
            _transport = transport;
            var rng = new SecureRandom();
            _crypto = new BcTlsCrypto(rng);

            var gen = new RsaKeyPairGenerator();
            gen.Init(new KeyGenerationParameters(rng, 2048));
            AsymmetricCipherKeyPair keyPair = gen.GenerateKeyPair();
            _privateKey = keyPair.Private;

            var name = new X509Name("CN=dtls-loopback-test");
            var certGen = new Org.BouncyCastle.X509.X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigInteger.ValueOf(1));
            certGen.SetIssuerDN(name);
            certGen.SetSubjectDN(name);
            certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            certGen.SetPublicKey(keyPair.Public);
            var sigFactory = new Asn1SignatureFactory("SHA256WITHRSA", _privateKey, rng);
            Org.BouncyCastle.X509.X509Certificate x509 = certGen.Generate(sigFactory);
            CertificateDer = x509.GetEncoded();

            var tlsCert = new BcTlsCertificate(_crypto, x509.CertificateStructure);
            _certificate = new Certificate(new TlsCertificate[] { tlsCert });

            _thread = new Thread(RunLoop) { IsBackground = true, Name = "dtls-test-server" };
        }

        /// <summary>Starts the server handshake + echo loop on its background thread.</summary>
        public void Start() => _thread.Start();

        void RunLoop()
        {
            try
            {
                var protocol = new DtlsServerProtocol();
                var server = new EchoTlsServer(_crypto, _certificate, _privateKey);
                using var bridge = new ServerDatagramBridge(_transport);
                DtlsTransport dtls = protocol.Accept(server, bridge);
                byte[] buffer = new byte[2048];
                while (true)
                {
                    int read = dtls.Receive(buffer, 0, buffer.Length, 30000);
                    if (read < 0) break;       // 30s idle ⇒ stop
                    if (read == 0) continue;
                    dtls.Send(buffer, 0, read); // echo the plaintext back
                }
                dtls.Close();
            }
            catch (Exception e) { Failure = e; }
        }

        public void Dispose() { }

        /// <summary>
        /// Test-side sync↔async bridge mirroring the production one: a background loop pulls datagrams off the async
        /// <see cref="IDatagramTransport"/> into a queue that BouncyCastle's blocking <see cref="DatagramTransport.Receive(byte[],int,int,int)"/>
        /// drains; sends run synchronously. Server-only scaffolding.
        /// </summary>
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

        /// <summary>The server-side <see cref="TlsServer"/>: DTLS 1.2, AEAD suites, RSA signer credentials from the self-signed cert.</summary>
        sealed class EchoTlsServer : DefaultTlsServer
        {
            readonly BcTlsCrypto _crypto;
            readonly Certificate _certificate;
            readonly AsymmetricKeyParameter _privateKey;

            public EchoTlsServer(BcTlsCrypto crypto, Certificate certificate, AsymmetricKeyParameter privateKey)
                : base(crypto)
            {
                _crypto = crypto;
                _certificate = certificate;
                _privateKey = privateKey;
            }

            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

            protected override int[] GetSupportedCipherSuites() => new[]
            {
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            };

            // ECDHE_RSA / DHE_RSA select an RSA signer; TLS_RSA selects an RSA decryptor.
            protected override TlsCredentialedSigner GetRsaSignerCredentials()
            {
                var sah = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
                return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), _crypto, _privateKey, _certificate, sah);
            }

            protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
                => new BcDefaultTlsCredentialedDecryptor(_crypto, _certificate, _privateKey);
        }
    }
}
