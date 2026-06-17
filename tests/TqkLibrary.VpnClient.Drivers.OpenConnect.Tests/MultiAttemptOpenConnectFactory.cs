using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Transport;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Tests
{
    /// <summary>
    /// An <see cref="IOpenConnectTransportFactory"/> that builds a <i>fresh</i> in-process byte-stream pair and a fresh
    /// in-process ocserv responder on <b>every</b> <see cref="ConnectAsync"/> — so a re-establish (the V.5 rekey path,
    /// which connects a brand-new tunnel make-before-break) gets a new server each time, exactly as a real gateway
    /// would. The client end of each pair is handed back; the server end is driven by a throwaway
    /// <see cref="SimulatedOpenConnectServer"/>. Each spawned server is tracked so a test can assert on the latest one
    /// (e.g. the rekeyed tunnel echoes traffic).
    /// </summary>
    sealed class MultiAttemptOpenConnectFactory : IOpenConnectTransportFactory
    {
        readonly string _user;
        readonly string _pass;
        readonly int _dpdSeconds;
        readonly int _keepaliveSeconds;
        readonly string? _rekeyMethod;
        readonly int _rekeyTime;
        readonly Func<int, string> _addressForAttempt;
        readonly ConcurrentQueue<SimulatedOpenConnectServer> _servers = new();
        readonly CancellationTokenSource _serversCts = new();
        int _attempts;

        public MultiAttemptOpenConnectFactory(string user, string pass,
            int dpdSeconds = 30, int keepaliveSeconds = 0,
            string? rekeyMethod = "new-tunnel", int rekeyTime = 0,
            Func<int, string>? addressForAttempt = null)
        {
            _user = user;
            _pass = pass;
            _dpdSeconds = dpdSeconds;
            _keepaliveSeconds = keepaliveSeconds;
            _rekeyMethod = rekeyMethod;
            _rekeyTime = rekeyTime;
            _addressForAttempt = addressForAttempt ?? (_ => "10.10.0.5");
        }

        /// <summary>How many tunnels (connect + each rekey re-establish) the client has opened through this factory.</summary>
        public int Attempts => Volatile.Read(ref _attempts);

        /// <summary>The most recently spawned server (the live tunnel after the latest connect/rekey).</summary>
        public SimulatedOpenConnectServer? LastServer { get; private set; }

        public Task<OpenConnectTransportHandle> ConnectAsync(string host, IPEndPoint remote, CancellationToken cancellationToken)
        {
            int attempt = Interlocked.Increment(ref _attempts);
            var link = new LoopbackByteStreamPair();
            var server = new SimulatedOpenConnectServer(link.Server, _user, _pass, _dpdSeconds, _keepaliveSeconds,
                address: _addressForAttempt(attempt), rekeyMethod: _rekeyMethod, rekeyTime: _rekeyTime);
            _servers.Enqueue(server);
            LastServer = server;
            // Run each server under the factory's own lifetime (not the transient connect token) so a rekeyed server
            // survives after the connect call that spawned it returns.
            _ = Task.Run(() => server.RunAsync(_serversCts.Token));
            return Task.FromResult(new OpenConnectTransportHandle(link.Client));
        }

        /// <summary>Stops every spawned server (call at the end of a test).</summary>
        public void StopAll() => _serversCts.Cancel();
    }
}
