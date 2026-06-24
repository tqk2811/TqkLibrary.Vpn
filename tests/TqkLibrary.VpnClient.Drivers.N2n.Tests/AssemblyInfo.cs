using Xunit;

// The end-to-end tests each drive a full n2n connect against an in-process supernode; registration + data bounce several
// datagrams through the loopback's thread-pool continuations. Serialise this assembly's classes to keep the in-process
// exchanges deterministic (a test-harness constraint only — real transports are async sockets).
[assembly: CollectionBehavior(DisableTestParallelization = true)]
