using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics;
using TqkLibrary.VpnClient.IpStack.Tcp;
using TqkLibrary.VpnClient.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// Pins the optional <see cref="ILogger"/> the deep TCP layer takes (roadmap Q.2, stretch): an injected logger must
    /// see the <see cref="VpnEventIds.ProtocolStep"/> state-transition trace (Closed → SynSent on the active open) while
    /// a null logger drives the exact same FSM. State transitions are rare (not per-packet), so the trace is cheap.
    /// </summary>
    public class TcpConnectionLoggingTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("10.0.0.2");

        [Fact]
        public void StartConnect_WithLogger_EmitsStateTransitionTrace()
        {
            var log = new CapturingLogger();
            // A no-op sink for outbound IP: this test only exercises the local FSM transition, not the wire.
            var conn = new TcpConnection(ClientIp, 12345, ServerIp, 80, _ => { }, logger: log);

            conn.StartConnect();

            Assert.Equal(TcpState.SynSent, conn.State);
            Assert.True(log.Captured(VpnEventIds.ProtocolStep));
            Assert.Contains(log.MessagesFor(VpnEventIds.ProtocolStep), m => m.Contains("Closed") && m.Contains("SynSent"));
        }

        [Fact]
        public void StartConnect_NullLogger_ReachesSynSent()
        {
            var conn = new TcpConnection(ClientIp, 12345, ServerIp, 80, _ => { }, logger: null);
            conn.StartConnect();
            Assert.Equal(TcpState.SynSent, conn.State);
        }

        sealed class CapturingLogger : ILogger
        {
            readonly ConcurrentQueue<(EventId Id, string Message)> _entries = new();

            public bool Captured(EventId id) => _entries.Any(e => e.Id.Id == id.Id);
            public IReadOnlyList<string> MessagesFor(EventId id)
                => _entries.Where(e => e.Id.Id == id.Id).Select(e => e.Message).ToArray();

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true; // capture everything, including Trace-level ProtocolStep

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => _entries.Enqueue((eventId, formatter(state, exception)));
        }
    }
}
