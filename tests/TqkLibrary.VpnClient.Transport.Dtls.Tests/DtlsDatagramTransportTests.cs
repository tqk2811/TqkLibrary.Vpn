using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.Dtls.Tests
{
    /// <summary>
    /// Offline DTLS 1.2 loopback tests: the real <see cref="DtlsDatagramTransport"/> (client) handshakes against an
    /// in-process BouncyCastle DTLS server over a <see cref="LoopbackDatagramLink"/>, then exchanges application
    /// datagrams. Covers the happy path, the optional certificate callback, and basic packet loss/reorder resilience.
    /// </summary>
    public class DtlsDatagramTransportTests
    {
        static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);
        static string Str(byte[] b, int n) => Encoding.UTF8.GetString(b, 0, n);

        [Fact]
        public async Task Handshake_completes_over_lossless_loopback()
        {
            var link = new LoopbackDatagramLink();
            using var server = new SimulatedDtlsServer(link.Server);
            server.Start();

            var client = new DtlsDatagramTransport(link.Client);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await client.ConnectAsync(cts.Token);

            Assert.True(client.SendLimit > 0);
            Assert.True(client.ReceiveLimit > 0);
            Assert.Null(server.Failure);

            await client.DisposeAsync();
        }

        [Fact]
        public async Task Round_trip_echoes_multiple_datagrams_both_directions()
        {
            var link = new LoopbackDatagramLink();
            using var server = new SimulatedDtlsServer(link.Server);
            server.Start();

            var client = new DtlsDatagramTransport(link.Client);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await client.ConnectAsync(cts.Token);

            // Send several distinct datagrams; the echo server returns each as one DTLS record (boundaries preserved).
            for (int i = 0; i < 5; i++)
            {
                byte[] payload = Bytes($"datagram-{i}-{new string((char)('a' + i), i * 7)}");
                await client.SendAsync(payload, cts.Token);

                byte[] rx = new byte[2048];
                int n = await client.ReceiveAsync(rx, cts.Token);
                Assert.Equal(payload.Length, n);
                Assert.Equal(payload, rx.AsSpan(0, n).ToArray());
            }

            Assert.Null(server.Failure);
            await client.DisposeAsync();
        }

        [Fact]
        public async Task Single_byte_payload_round_trips()
        {
            // DTLS application_data records carry at least one byte (BouncyCastle rejects a zero-length Send), so the
            // smallest datagram a consumer can push through is one byte — confirm that minimum round-trips intact.
            var link = new LoopbackDatagramLink();
            using var server = new SimulatedDtlsServer(link.Server);
            server.Start();

            var client = new DtlsDatagramTransport(link.Client);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await client.ConnectAsync(cts.Token);

            await client.SendAsync(new byte[] { 0x2A }, cts.Token);
            byte[] rx = new byte[16];
            int n = await client.ReceiveAsync(rx, cts.Token);
            Assert.Equal(1, n);
            Assert.Equal(0x2A, rx[0]);

            await client.DisposeAsync();
        }

        [Fact]
        public async Task Certificate_callback_observes_server_certificate()
        {
            var link = new LoopbackDatagramLink();
            using var server = new SimulatedDtlsServer(link.Server);
            server.Start();

            byte[]? observedFirstCert = null;
            var client = new DtlsDatagramTransport(link.Client, certificateValidationCallback: cert =>
            {
                if (cert.Certificate.Length > 0)
                    observedFirstCert = cert.Certificate.GetCertificateAt(0).GetEncoded();
                return true; // accept
            });

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await client.ConnectAsync(cts.Token);

            Assert.NotNull(observedFirstCert);
            Assert.Equal(server.CertificateDer, observedFirstCert);

            await client.DisposeAsync();
        }

        [Fact]
        public async Task Rejecting_certificate_aborts_the_handshake()
        {
            var link = new LoopbackDatagramLink();
            using var server = new SimulatedDtlsServer(link.Server);
            server.Start();

            var client = new DtlsDatagramTransport(link.Client, certificateValidationCallback: _ => false); // reject

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await Assert.ThrowsAnyAsync<Exception>(() => client.ConnectAsync(cts.Token).AsTask());

            await client.DisposeAsync();
        }

        [Fact]
        public async Task Handshake_survives_a_dropped_then_retransmitted_flight()
        {
            var link = new LoopbackDatagramLink();
            using var server = new SimulatedDtlsServer(link.Server);
            server.Start();

            // Drop the very first datagram each side emits during the handshake; DTLS retransmits its flights, so the
            // handshake must still complete (just slower). After two passes everything flows normally.
            link.Client.NetworkConditions = DropFirst();
            link.Server.NetworkConditions = DropFirst();

            var client = new DtlsDatagramTransport(link.Client);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            await client.ConnectAsync(cts.Token);

            await client.SendAsync(Bytes("survived-loss"), cts.Token);
            byte[] rx = new byte[256];
            int n = await client.ReceiveAsync(rx, cts.Token);
            Assert.Equal("survived-loss", Str(rx, n));

            Assert.Null(server.Failure);
            await client.DisposeAsync();
        }

        [Fact]
        public async Task Reordered_handshake_records_still_complete()
        {
            var link = new LoopbackDatagramLink();
            using var server = new SimulatedDtlsServer(link.Server);
            server.Start();

            // Swap the first two datagrams the server sends (deliver #2 before #1), exercising the client's out-of-order
            // record handling; everything after passes through in order so nothing is ever permanently held.
            link.Server.NetworkConditions = SwapFirstTwo();

            var client = new DtlsDatagramTransport(link.Client);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            await client.ConnectAsync(cts.Token);

            await client.SendAsync(Bytes("reordered-ok"), cts.Token);
            byte[] rx = new byte[256];
            int n = await client.ReceiveAsync(rx, cts.Token);
            Assert.Equal("reordered-ok", Str(rx, n));

            Assert.Null(server.Failure);
            await client.DisposeAsync();
        }

        /// <summary>Drops only the first datagram, then passes everything through unchanged.</summary>
        static LoopbackDatagramLink.NetworkCondition DropFirst()
        {
            bool dropped = false;
            return datagram =>
            {
                if (!dropped) { dropped = true; return Enumerable.Empty<byte[]>(); }
                return new[] { datagram };
            };
        }

        /// <summary>Holds the first datagram and releases it right after the second (delivers #2 before #1), then passes the rest through in order.</summary>
        static LoopbackDatagramLink.NetworkCondition SwapFirstTwo()
        {
            int seen = 0;
            byte[]? held = null;
            return datagram =>
            {
                seen++;
                if (seen == 1) { held = datagram; return Enumerable.Empty<byte[]>(); } // hold #1
                if (seen == 2) { byte[] first = held!; held = null; return new[] { datagram, first }; } // #2 then #1
                return new[] { datagram }; // everything after: in order
            };
        }
    }
}
