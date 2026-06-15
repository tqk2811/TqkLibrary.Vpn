using Xunit;

// The end-to-end handshake tests (tun + tap) each drive a full OpenVPN connect against an in-process responder running
// two SslStream handshakes over a blocking in-memory bridge; tap additionally bounces several ARP round-trips through
// the loopback's thread-pool continuations. Run in parallel across classes on a low-core box, those blocking in-process
// handshakes can starve the thread pool. Real transports are async sockets, so this is a test-harness constraint only —
// serialise this assembly's classes to keep the in-process handshakes deterministic.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
