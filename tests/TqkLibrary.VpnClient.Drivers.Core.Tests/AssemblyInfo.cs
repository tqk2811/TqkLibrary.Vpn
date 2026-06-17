using Xunit;

// The supervisor tests each spin up a reconnect loop on the thread pool and poll for state transitions. Run in
// parallel on a low-core box they can starve each other; serialise this assembly's classes for deterministic timing.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
