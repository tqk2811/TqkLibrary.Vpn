using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Transport.Tls;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.Tls.Tests
{
    /// <summary>
    /// Offline coverage for the shared TLS byte stream (<see cref="TlsByteStream"/>, roadmap F.1). Each test runs a real
    /// TLS handshake against a loopback <see cref="TcpListener"/> (no external network — so this is NOT marked
    /// Integration), proving the cert-validation callback reaches <see cref="SslStream"/> and gates the handshake (P0.6),
    /// the server certificate is captured for the SSTP crypto binding, both constructors connect, and data round-trips.
    /// </summary>
    public class TlsByteStreamTests
    {
        [Fact]
        public async Task Connect_NoCallback_AcceptsSelfSignedCert_AndCapturesIt()
        {
            using var serverCert = CreateServerCert();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = RunTlsServerAsync(listener, serverCert);

                using var client = new TlsByteStream("127.0.0.1", port); // no callback ⇒ accept any cert
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(cts.Token);

                Assert.NotNull(client.RemoteCertificate);
                Assert.Equal(serverCert.Thumbprint, client.RemoteCertificate!.Thumbprint);
                await server;
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public async Task Connect_PreResolvedEndpoint_Works_AndCapturesCert()
        {
            using var serverCert = CreateServerCert();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = RunTlsServerAsync(listener, serverCert);

                using var client = new TlsByteStream("127.0.0.1", new IPEndPoint(IPAddress.Loopback, port));
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(cts.Token);

                Assert.NotNull(client.RemoteCertificate);
                Assert.Equal(serverCert.Thumbprint, client.RemoteCertificate!.Thumbprint);
                await server;
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public async Task Connect_Callback_ReceivesServerCert_AndAccepts()
        {
            using var serverCert = CreateServerCert();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = RunTlsServerAsync(listener, serverCert);

                string? seenThumbprint = null;
                SslPolicyErrors seenErrors = SslPolicyErrors.None;
                RemoteCertificateValidationCallback callback = (sender, certificate, chain, errors) =>
                {
                    using var seen = new X509Certificate2(certificate!);
                    seenThumbprint = seen.Thumbprint;
                    seenErrors = errors;
                    return true; // accept despite the self-signed chain error
                };

                using var client = new TlsByteStream("127.0.0.1", port, callback);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(cts.Token);

                Assert.Equal(serverCert.Thumbprint, seenThumbprint);
                Assert.NotEqual(SslPolicyErrors.None, seenErrors); // self-signed ⇒ chain/name error surfaced to the callback
                Assert.NotNull(client.RemoteCertificate);          // captured for the crypto binding regardless
                await server;
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public async Task Connect_CallbackRejects_ThrowsAuthenticationException()
        {
            using var serverCert = CreateServerCert();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = RunTlsServerAsync(listener, serverCert);

                using var client = new TlsByteStream("127.0.0.1", port, (sender, certificate, chain, errors) => false);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

                await Assert.ThrowsAsync<AuthenticationException>(() => client.ConnectAsync(cts.Token).AsTask());
                await server; // the server-side handshake fails too; RunTlsServerAsync swallows it
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public async Task ReadWrite_RoundTripsOverTls()
        {
            using var serverCert = CreateServerCert();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                // Server: handshake then echo the first 5 bytes back.
                Task server = Task.Run(async () =>
                {
                    try
                    {
                        using TcpClient s = await listener.AcceptTcpClientAsync();
                        using var ssl = new SslStream(s.GetStream(), leaveInnerStreamOpen: false);
                        await ssl.AuthenticateAsServerAsync(serverCert);
                        byte[] buf = new byte[5];
                        int read = 0;
                        while (read < buf.Length)
                        {
                            int r = await ssl.ReadAsync(buf, read, buf.Length - read);
                            if (r == 0) break;
                            read += r;
                        }
                        await ssl.WriteAsync(buf, 0, read);
                    }
                    catch { }
                });

                using var client = new TlsByteStream("127.0.0.1", port);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(cts.Token);

                await client.WriteAsync(new byte[] { 1, 2, 3, 4, 5 }, cts.Token);
                byte[] echo = new byte[5];
                int got = 0;
                while (got < echo.Length)
                {
                    int r = await client.ReadAsync(echo.AsMemory(got), cts.Token);
                    if (r == 0) break;
                    got += r;
                }

                Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, echo);
                await server;
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public async Task ReadAsync_BeforeConnect_Throws()
        {
            using var client = new TlsByteStream("127.0.0.1", 443);
            await Assert.ThrowsAsync<InvalidOperationException>(() => client.ReadAsync(new byte[4]).AsTask());
        }

        // Accepts one TLS client over loopback and completes the server handshake; swallows the failure a rejecting
        // client triggers. The handshake completing is all the client side needs, so it returns without reading data.
        static async Task RunTlsServerAsync(TcpListener listener, X509Certificate2 cert)
        {
            try
            {
                using TcpClient server = await listener.AcceptTcpClientAsync();
                using var ssl = new SslStream(server.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(cert);
            }
            catch { /* client rejected the cert or closed early — expected in the reject test */ }
        }

        // A self-signed server cert, round-tripped through PFX so Windows SChannel can use its private key in
        // AuthenticateAsServerAsync (an ephemeral key from CreateSelfSigned alone is rejected there).
        static X509Certificate2 CreateServerCert()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=tls-transport-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(10));
            return new X509Certificate2(ephemeral.Export(X509ContentType.Pfx));
        }
    }
}
