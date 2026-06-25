using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.Dtls.Tests
{
    /// <summary>
    /// Offline DTLS 1.2 <b>PSK</b> loopback tests: the real <see cref="DtlsDatagramTransport"/> (driving
    /// <c>OpenConnectDtls12PskClient</c> via <see cref="DtlsPskParameters"/>) runs a full DTLS 1.2 PSK handshake against
    /// an in-process <see cref="SimulatedDtlsPskServer"/>, then exchanges application datagrams. This is the modern
    /// OpenConnect <c>PSK-NEGOTIATE</c> path (no certificate, no legacy resumption), exercised without a live ocserv.
    /// </summary>
    public class DtlsPskHandshakeTests
    {
        static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);
        static string Str(byte[] b, int n) => Encoding.UTF8.GetString(b, 0, n);

        static (byte[] identity, byte[] pskKey, byte[] sessionId) NewParams()
        {
            byte[] identity = Encoding.ASCII.GetBytes("psk");
            byte[] pskKey = new byte[32];
            byte[] sessionId = new byte[32]; // X-DTLS-App-ID is 16–32 bytes; OpenConnect uses 32
            var rng = new SecureRandom();
            rng.NextBytes(pskKey);
            rng.NextBytes(sessionId);
            return (identity, pskKey, sessionId);
        }

        [Fact]
        public async Task Psk_handshake_completes_and_server_sees_the_identity()
        {
            (byte[] identity, byte[] pskKey, byte[] sessionId) = NewParams();
            var link = new LoopbackDatagramLink();
            using var server = new SimulatedDtlsPskServer(link.Server, identity, pskKey);
            server.Start();

            var psk = new DtlsPskParameters(identity, pskKey, sessionId);
            var client = new DtlsDatagramTransport(link.Client, psk: psk);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await client.ConnectAsync(cts.Token);

            Assert.True(client.SendLimit > 0);
            Assert.True(client.ReceiveLimit > 0);
            Assert.Null(server.Failure);
            Assert.NotNull(server.ObservedIdentity);
            Assert.Equal(identity, server.ObservedIdentity);

            await client.DisposeAsync();
        }

        [Fact]
        public async Task Psk_round_trip_echoes_datagrams_both_directions()
        {
            (byte[] identity, byte[] pskKey, byte[] sessionId) = NewParams();
            var link = new LoopbackDatagramLink();
            using var server = new SimulatedDtlsPskServer(link.Server, identity, pskKey);
            server.Start();

            var psk = new DtlsPskParameters(identity, pskKey, sessionId);
            var client = new DtlsDatagramTransport(link.Client, psk: psk);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await client.ConnectAsync(cts.Token);

            for (int i = 0; i < 5; i++)
            {
                byte[] payload = Bytes($"psk-datagram-{i}");
                await client.SendAsync(payload, cts.Token);
                byte[] rx = new byte[2048];
                int n = await client.ReceiveAsync(rx, cts.Token);
                Assert.Equal(payload, rx.AsSpan(0, n).ToArray());
            }

            Assert.Null(server.Failure);
            await client.DisposeAsync();
        }

        [Fact]
        public async Task Psk_handshake_fails_on_a_wrong_key()
        {
            (byte[] identity, byte[] pskKey, byte[] sessionId) = NewParams();
            var link = new LoopbackDatagramLink();
            // Server expects a different key than the client offers ⇒ the Finished verification must fail.
            byte[] serverKey = (byte[])pskKey.Clone();
            serverKey[0] ^= 0xFF;
            using var server = new SimulatedDtlsPskServer(link.Server, identity, serverKey);
            server.Start();

            var psk = new DtlsPskParameters(identity, pskKey, sessionId);
            var client = new DtlsDatagramTransport(link.Client, psk: psk);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await Assert.ThrowsAnyAsync<Exception>(() => client.ConnectAsync(cts.Token).AsTask());

            await client.DisposeAsync();
        }
    }
}
