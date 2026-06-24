using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Ipsec.Esp;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Esp.Tests
{
    /// <summary>
    /// Pins the optional <see cref="ILogger"/> the deep ESP layer takes (roadmap Q.2): an injected logger must see the
    /// SA-install <see cref="VpnEventIds.ProtocolStep"/> trace and the classified <see cref="VpnEventIds.PacketDropped"/>
    /// reasons (replay, decrypt-failed) — while a null logger runs the exact same protect/unprotect path.
    /// </summary>
    public class EspSessionLoggingTests
    {
        const uint SpiAToB = 0xAABBCCDD;
        const uint SpiBToA = 0x11223344;

        static byte[] Fill(int n, byte seed)
        {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte)(seed + i);
            return b;
        }

        // A→B sender (silent) + B→A receiver fitted with a capturing logger so its drop reasons can be asserted.
        static (EspSession a, EspSession b, CapturingLogger log) PairWithLoggedReceiver()
        {
            byte[] encAb = Fill(32, 0x01), integAb = Fill(32, 0x02);
            byte[] encBa = Fill(32, 0x03), integBa = Fill(32, 0x04);
            EspCipherSuite aToB = EspCipherSuite.AesCbcHmacSha256(encAb, integAb);
            EspCipherSuite bToA = EspCipherSuite.AesCbcHmacSha256(encBa, integBa);
            var log = new CapturingLogger();
            var a = new EspSession(SpiAToB, aToB, SpiBToA, bToA);
            var b = new EspSession(SpiBToA, bToA, SpiAToB, aToB, log);
            return (a, b, log);
        }

        [Fact]
        public void SaInstall_EmitsProtocolStepTrace()
        {
            (_, _, CapturingLogger log) = PairWithLoggedReceiver();
            Assert.True(log.Captured(VpnEventIds.ProtocolStep));
            Assert.Contains(log.MessagesFor(VpnEventIds.ProtocolStep), m => m.Contains("SA installed"));
        }

        [Fact]
        public void Replay_LogsPacketDroppedWithReplayReason()
        {
            (EspSession a, EspSession b, CapturingLogger log) = PairWithLoggedReceiver();
            byte[] packet = a.Protect(Fill(20, 0x99), EspConstants.NextHeaderUdp);
            Assert.True(b.TryUnprotect(packet, out _, out _));
            Assert.False(b.TryUnprotect(packet, out _, out _)); // same sequence again → replay

            Assert.Contains(log.Drops, d => d.Reason == VpnDropReason.Replay);
        }

        [Fact]
        public void TamperedIcv_LogsPacketDroppedWithDecryptFailedReason()
        {
            (EspSession a, EspSession b, CapturingLogger log) = PairWithLoggedReceiver();
            byte[] packet = a.Protect(Fill(40, 0x33), EspConstants.NextHeaderUdp);
            packet[^1] ^= 0xFF; // flip the last ICV byte
            Assert.False(b.TryUnprotect(packet, out _, out _));

            Assert.Contains(log.Drops, d => d.Reason == VpnDropReason.DecryptFailed);
        }

        [Fact]
        public void NullLogger_RoundTripUnaffected()
        {
            byte[] enc = Fill(32, 0x01), integ = Fill(32, 0x02);
            EspCipherSuite suite = EspCipherSuite.AesCbcHmacSha256(enc, integ);
            var a = new EspSession(SpiAToB, suite, SpiBToA, EspCipherSuite.AesCbcHmacSha256(Fill(32, 5), Fill(32, 6)), logger: null);
            var b = new EspSession(SpiBToA, EspCipherSuite.AesCbcHmacSha256(Fill(32, 5), Fill(32, 6)), SpiAToB, suite, logger: null);

            byte[] packet = a.Protect(Fill(64, 0x42), EspConstants.NextHeaderUdp);
            Assert.True(b.TryUnprotect(packet, out byte[] recovered, out _));
            Assert.Equal(Fill(64, 0x42), recovered);
        }

        sealed class CapturingLogger : ILogger
        {
            readonly ConcurrentQueue<(EventId Id, string Message)> _entries = new();

            public bool Captured(EventId id) => _entries.Any(e => e.Id.Id == id.Id);
            public IReadOnlyList<string> MessagesFor(EventId id)
                => _entries.Where(e => e.Id.Id == id.Id).Select(e => e.Message).ToArray();

            // Drop entries land on PacketDropped and carry the reason as a structured field, which the default formatter
            // renders into the message text — assert on the parsed reason via the message instead of re-parsing fields.
            public IReadOnlyList<(VpnDropReason Reason, string Message)> Drops
                => _entries.Where(e => e.Id.Id == VpnEventIds.PacketDropped.Id)
                    .Select(e => (ReasonFromMessage(e.Message), e.Message)).ToArray();

            static VpnDropReason ReasonFromMessage(string message)
            {
                foreach (VpnDropReason reason in Enum.GetValues(typeof(VpnDropReason)))
                    if (message.Contains(reason.ToString())) return reason;
                return VpnDropReason.Unspecified;
            }

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => _entries.Enqueue((eventId, formatter(state, exception)));
        }
    }
}
