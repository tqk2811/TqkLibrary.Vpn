using Xunit;

// Each test drives a full DTLS handshake against an in-process BouncyCastle server whose handshake/echo loop runs on a
// dedicated background thread, with the client's blocking record I/O offloaded to the thread pool. Run in parallel on a
// low-core box, those background threads can starve the pool and stall handshakes. Real transports are async UDP
// sockets, so this is a test-harness constraint only — serialise this assembly's classes for determinism.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
