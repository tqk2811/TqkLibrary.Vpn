using Xunit;

// The end-to-end tests each drive a full vtun connect against an in-process responder; the handshake + frame exchanges
// bounce several blocks through the loopback's blocking pipe on background threads. Serialise this assembly's classes
// to keep the in-process exchanges deterministic (a test-harness constraint only — real transports are async sockets).
[assembly: CollectionBehavior(DisableTestParallelization = true)]
